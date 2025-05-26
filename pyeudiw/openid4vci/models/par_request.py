import logging
from typing import List
from urllib.parse import urlparse

from pydantic import model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException
from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel, CONFIG_CTX, CLIENT_ID_CTX
from pyeudiw.openid4vci.utils.date import DateUtils

logger = logging.getLogger(__name__)

ENTITY_ID_CTX = "entity_id"
PAR_ENDPOINT = "par"
OPEN_ID_CREDENTIAL_TYPE = "openid_credential"

class AuthorizationDetail(OpenId4VciBaseModel):
  type: str = None
  credential_configuration_id: str = None

  @model_validator(mode='after')
  def check_authorization_detail(self) -> "AuthorizationDetail":
    self.validate_type()
    self.validate_credential_configuration_id()
    return self

  def validate_credential_configuration_id(self):
    self.credential_configuration_id = self.strip(self.credential_configuration_id)
    self.check_missing_parameter(self.credential_configuration_id, "authorization_details.credential_configuration_id", PAR_ENDPOINT)

    credential_configurations_supported = self.get_config().get_credential_configurations_supported()
    if self.credential_configuration_id not in [ccs.id for ccs in credential_configurations_supported.values()]:
      logger.error(f"invalid credential_configuration_ids {self.credential_configuration_id} in request `par` endpoint")
      raise InvalidRequestException("invalid `authorization_details.credential_configuration_id` parameter")

  def validate_type(self):
    self.type = self.strip(self.type)
    self.check_missing_parameter(self.type, "authorization_details.type", PAR_ENDPOINT)
    if self.type != OPEN_ID_CREDENTIAL_TYPE :
      logger.error(f"invalid authorization_details.type {self.type} in request `par` endpoint")
      raise InvalidRequestException("invalid `authorization_details.type` parameter")



class ParRequest(OpenId4VciBaseModel):
  iss: str = None
  aud: str = None
  exp: int = None
  iat: int = None
  response_type: str = None
  response_mode: str = None
  client_id: str = None
  state: str = None
  code_challenge: str = None
  code_challenge_method: str = None
  scope: str = None
  authorization_details: List[AuthorizationDetail] = None
  redirect_uri: str = None
  jti: str = None
  issuer_state: str = None

  @model_validator(mode='after')
  def check_par_request(self) -> "ParRequest":
    config = self.get_config().get_oauth_authorization_server()
    req_client_id = self.get_ctx(CLIENT_ID_CTX)
    self.validate_iss(req_client_id)
    self.validate_aud()
    self.validate_state()
    self.validate_client_id(req_client_id)

    if not DateUtils.is_valid_unix_timestamp(self.exp):
      logger.error(f"invalid exp {self.exp} in request `par` endpoint")
      raise InvalidRequestException("invalid `exp` parameter")

    if not DateUtils.is_valid_unix_timestamp(self.iat):
      logger.error(f"invalid iat {self.iat} in request `par` endpoint")
      raise InvalidRequestException("invalid `iat` parameter")

    if int(self.exp) - int(self.iat) > 300:
      logger.error("expired request token in `par` endpoint")
      raise InvalidRequestException("expired token")

    self.validate_response_type(config.response_types_supported)
    self.validate_response_mode(config.response_modes_supported)
    self.validate_code_challenge()
    self.validate_code_challenge_method(config.code_challenge_methods_supported)
    self.validate_scope(config.scopes_supported)
    self.validate_redirect_uri()
    self.validate_jti()
    self.validate_authorization_details()
    return self

  def validate_authorization_details(self):
    self.check_missing_parameter(self.authorization_details, "authorization_details", PAR_ENDPOINT)
    AuthorizationDetail.model_validate(
      self.authorization_details,
      context={CONFIG_CTX: self.get_config()}
    )


  def validate_scope(self, scopes_supported: list[str]):
    self.scope = self.strip(self.scope)
    self.check_missing_parameter(self.scope, "scope", PAR_ENDPOINT)
    scopes = self.scope.split(" ")
    for s in scopes:
      if s not in scopes_supported:
        logger.error(f"invalid scope value '{s}' in `par` endpoint")
        raise InvalidRequestException("invalid `scope` parameter")


  def validate_code_challenge(self):
    self.code_challenge = self.strip(self.code_challenge)
    self.check_missing_parameter(self.code_challenge, "code_challenge", PAR_ENDPOINT)

  def validate_code_challenge_method(self, code_challenge_methods_supported: list[str]):
    self.code_challenge_method = self.strip(self.code_challenge_method)
    self.check_missing_parameter(self.code_challenge_method, "code_challenge_method", PAR_ENDPOINT)
    if self.code_challenge_method not in code_challenge_methods_supported:
      logger.error(f"invalid code_challenge_method {self.code_challenge_method} in `par` endpoint")
      raise InvalidRequestException("invalid `code_challenge_method` parameter")

  def validate_response_mode(self, response_modes_supported: list[str]):
    self.response_mode = self.strip(self.response_mode)
    self.check_missing_parameter(self.response_mode, "response_mode", PAR_ENDPOINT)
    if self.response_mode not in response_modes_supported:
      logger.error(f"invalid response_mode {self.response_mode} in `par` endpoint")
      raise InvalidRequestException("invalid `response_mode` parameter")

  def validate_response_type(self, response_types_supported: list[str]):
    self.response_type = self.strip(self.response_type)
    self.check_missing_parameter(self.response_type, "response_type", PAR_ENDPOINT)
    if self.response_type not in response_types_supported:
      logger.error(f"invalid response type {self.response_type} in `par` endpoint")
      raise InvalidRequestException("invalid `response_type` parameter")

  def validate_client_id(self, req_client_id: str):
    self.client_id = self.strip(self.client_id)
    self.check_missing_parameter(self.client_id, "client_id", PAR_ENDPOINT)
    if self.client_id != req_client_id:
      logger.error(f"invalid request client_id {self.client_id} in `par` endpoint")
      raise InvalidRequestException("invalid `client_id` parameter")

  def validate_state(self):
    self.state = self.strip(self.state)
    self.check_missing_parameter(self.state, "state", PAR_ENDPOINT)
    if len(self.state) < 32 or not self.state.isalnum():
      logger.error(f"invalid state {self.state} in `par` endpoint")
      raise InvalidRequestException("invalid `state` parameter")


  def validate_iss(self, req_client_id: str):
    self.iss = self.strip(self.iss)
    self.check_missing_parameter(self.iss, "iss", PAR_ENDPOINT)
    if self.iss != req_client_id:
      logger.error(f"invalid request iss {self.iss} in `par` endpoint")
      raise InvalidRequestException("invalid `iss` parameter")

  def validate_aud(self):
    self.aud = self.strip(self.aud)
    self.check_missing_parameter(self.aud, "aud", PAR_ENDPOINT)
    if self.aud != self.get_ctx(ENTITY_ID_CTX):
      logger.error(f"invalid request `aud` {self.aud} in `par` endpoint")
      raise InvalidRequestException("invalid `aud` parameter")

  def validate_redirect_uri(self):
    self.redirect_uri = self.strip(self.redirect_uri)
    self.check_missing_parameter(self.redirect_uri, "redirect_uri", PAR_ENDPOINT)

    try:
      parsed_redirect_uri = urlparse(self.redirect_uri)
      if not parsed_redirect_uri.scheme or not parsed_redirect_uri.netloc or not parsed_redirect_uri.path:
        logger.error(f"invalid redirect_uri value '{self.redirect_uri}' in `par` endpoint")
        raise InvalidRequestException("invalid `redirect_uri` parameter")
    except Exception as e:
      logger.error(f"invalid redirect_uri value '{self.redirect_uri}' in `par` endpoint: {e}")
      raise InvalidRequestException("invalid `redirect_uri` parameter")

  def validate_jti(self):
    self.jti = self.strip(self.jti)
    self.check_missing_parameter(self.jti, "jti", PAR_ENDPOINT)

    if self.iss not in self.jti:
      logger.error(f"invalid jti {self.jti} in request `par` endpoint")
      raise InvalidRequestException("invalid `jti` parameter")

    if len(self.jti) - len(self.iss) == 0:
      logger.error(f"invalid jti {self.jti} in request `par` endpoint")
      raise InvalidRequestException("invalid `jti` parameter")
