import logging
from typing import List
from urllib.parse import urlparse

from pydantic import model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException
from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel, CONFIG_CTX, CLIENT_ID_CTX
from pyeudiw.openid4vci.utils.config import Config
from pyeudiw.openid4vci.utils.date import DateUtils

logger = logging.getLogger(__name__)

ENTITY_ID_CTX = "entity_id"

class AuthorizationDetail(OpenId4VciBaseModel):
  type: str
  credential_configuration_id: str

  @model_validator(mode='after')
  def check_authorization_detail(self) -> "AuthorizationDetail":
    if not self.type :
      logger.error("missing authorization_details.type in request `par` endpoint")
      raise InvalidRequestException("missing `authorization_details.type` parameter")

    if self.type != "openid_credential" :
      logger.error(f"invalid authorization_details.type {self.type} in request `par` endpoint")
      raise InvalidRequestException("invalid `authorization_details.type` parameter")

    if self.credential_configuration_id not in [ccs["id"] for ccs in Config(self.__pydantic_context__.get("config")).get_credential_configurations_supported().values()]:
      logger.error(f"invalid authorization_details.credential_configuration_id {self.credential_configuration_id} in request `par` endpoint")
      raise InvalidRequestException("invalid `authorization_details.credential_configuration_id` parameter")

    return self


class ParRequest(OpenId4VciBaseModel):
  iss: str
  aud: str
  exp: int
  iat: int
  response_type: str
  response_mode: str
  client_id: str
  state: str
  code_challenge: str
  code_challenge_method: str
  scope: str
  authorization_details: List[AuthorizationDetail]
  redirect_uri: str
  jti: str
  issuer_state: str

  @model_validator(mode='after')
  def check_par_request(self) -> "ParRequest":
    config = self.get_config().get_oauth_authorization_server()

    if not self.iss:
      logger.error("missing iss in request `par` endpoint")
      raise InvalidRequestException("missing `iss` parameter")

    req_client_id = self.get_ctx(CLIENT_ID_CTX)
    if self.iss != req_client_id:
      logger.error(f"invalid request iss {self.iss} in `par` endpoint")
      raise InvalidRequestException("invalid `iss` parameter")

    self.validate_aud()

    if not DateUtils.is_valid_unix_timestamp(self.exp):
      logger.error(f"invalid exp {self.exp} in request `par` endpoint")
      raise InvalidRequestException("invalid `exp` parameter")

    if not DateUtils.is_valid_unix_timestamp(self.iat):
      logger.error(f"invalid iat {self.iat} in request `par` endpoint")
      raise InvalidRequestException("invalid `iat` parameter")

    if int(self.exp) - int(self.iat) > 300:
      logger.error("expired request token in `par` endpoint")
      raise InvalidRequestException("expired token")

    if self.response_type not in config.response_types_supported:
      logger.error(f"invalid response type {self.response_type} in `par` endpoint")
      raise InvalidRequestException("invalid `response_type` parameter")

    if self.response_mode not in config.response_modes_supported:
      logger.error(f"invalid response_mode {self.response_mode} in `par` endpoint")
      raise InvalidRequestException("invalid `response_mode` parameter")

    if self.client_id != req_client_id:
      logger.error(f"invalid request client_id {self.client_id} in `par` endpoint")
      raise InvalidRequestException("invalid `request.client_id` parameter")

    if len(self.state) < 32 or not self.state.isalnum():
      logger.error(f"invalid state {self.state} in `par` endpoint")
      raise InvalidRequestException("invalid `state` parameter")

    if not self.code_challenge:
      logger.error("missing `code_challenge` in `par` endpoint request")
      raise InvalidRequestException("missing `code_challenge` parameter")

    if self.code_challenge_method not in config.code_challenge_methods_supported:
      logger.error(f"invalid code_challenge_method {self.code_challenge_method} in `par` endpoint")
      raise InvalidRequestException("invalid `code_challenge_method` parameter")

    scopes = self.scope.split(" ")
    for s in scopes:
      if s not in config.scopes_supported:
        logger.error(f"invalid scope value '{s}' in `par` endpoint")
        raise InvalidRequestException(f"invalid scope value '{s}'")

    AuthorizationDetail.model_validate(
      self.authorization_details,
      context = {CONFIG_CTX: self.get_config()})

    self.validate_redirect_uri()
    self.validate_jti()
    return self

  def validate_aud(self):
    if not self.aud:
      logger.error("missing aud in request `par` endpoint")
      raise InvalidRequestException("missing `aud` parameter")

    if self.aud != self.get_ctx(ENTITY_ID_CTX):
      logger.error(f"invalid request `aud` {self.aud} in `par` endpoint")
      raise InvalidRequestException("invalid `aud` parameter")

  def validate_redirect_uri(self):
    if not self.redirect_uri:
      logger.error("missing redirect_uri in request `par` endpoint")
      raise InvalidRequestException("missing `redirect_uri` parameter")

    try:
      parsed_redirect_uri = urlparse(self.redirect_uri)
      if not parsed_redirect_uri.scheme or not (parsed_redirect_uri.netloc or parsed_redirect_uri.path):
        logger.error(f"invalid redirect_uri value '{self.redirect_uri}' in `par` endpoint")
        raise InvalidRequestException("invalid redirect_uri")
    except Exception as e:
      logger.error(f"invalid redirect_uri value '{self.redirect_uri}' in `par` endpoint: {e}")
      raise InvalidRequestException("invalid redirect_uri")

  def validate_jti(self):
    if not self.jti:
      logger.error("missing jti in request `par` endpoint")
      raise InvalidRequestException("missing `jti` parameter")

    if self.iss not in self.jti:
      logger.error(f"invalid jti {self.jti} in request `par` endpoint")
      raise InvalidRequestException("invalid `jti` parameter")

    if len(self.jti) - len(self.iss) == 0:
      logger.error(f"invalid jti {self.jti} in request `par` endpoint")
      raise InvalidRequestException("invalid `jti` parameter")
