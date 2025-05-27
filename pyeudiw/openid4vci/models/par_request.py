import logging
from typing import List
from urllib.parse import urlparse

from pydantic import model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException
from pyeudiw.openid4vci.models.auhtorization_detail import AuthorizationDetail
from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel, CONFIG_CTX, CLIENT_ID_CTX, ENDPOINT_CTX
from pyeudiw.openid4vci.utils.date import DateUtils

logger = logging.getLogger(__name__)

ENTITY_ID_CTX = "entity_id"

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
    endpoint = self.get_ctx(ENDPOINT_CTX)
    self.validate_iss(req_client_id, endpoint)
    self.validate_aud(endpoint)
    self.validate_state(endpoint)
    self.validate_client_id(req_client_id, endpoint)

    if not DateUtils.is_valid_unix_timestamp(self.exp):
      logger.error(f"invalid exp {self.exp} in request `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `exp` parameter")

    if not DateUtils.is_valid_unix_timestamp(self.iat):
      logger.error(f"invalid iat {self.iat} in request `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `iat` parameter")

    if int(self.exp) - int(self.iat) > 300:
      logger.error(f"expired request token in `{endpoint}` endpoint")
      raise InvalidRequestException("expired token")

    self.validate_response_type(config.response_types_supported, endpoint)
    self.validate_response_mode(config.response_modes_supported, endpoint)
    self.validate_code_challenge(endpoint)
    self.validate_code_challenge_method(config.code_challenge_methods_supported, endpoint)
    self.validate_scope(config.scopes_supported, endpoint)
    self.validate_redirect_uri(endpoint)
    self.validate_jti(endpoint)
    self.validate_authorization_details(endpoint)
    return self

  def validate_authorization_details(self, endpoint: str):
    self.check_missing_parameter(self.authorization_details, "authorization_details", endpoint)
    for ad in self.authorization_details:
      AuthorizationDetail.model_validate(ad, context = {
        CONFIG_CTX: self.get_config(),
      })


  def validate_scope(self, scopes_supported: list[str], endpoint: str):
    self.scope = self.strip(self.scope)
    self.check_missing_parameter(self.scope, "scope", endpoint)
    scopes = self.scope.split(" ")
    for s in scopes:
      if s not in scopes_supported:
        logger.error(f"invalid scope value '{s}' in `{endpoint}` endpoint")
        raise InvalidRequestException("invalid `scope` parameter")


  def validate_code_challenge(self, endpoint: str):
    self.code_challenge = self.strip(self.code_challenge)
    self.check_missing_parameter(self.code_challenge, "code_challenge", endpoint)

  def validate_code_challenge_method(self, code_challenge_methods_supported: list[str], endpoint: str):
    self.code_challenge_method = self.strip(self.code_challenge_method)
    self.check_missing_parameter(self.code_challenge_method, "code_challenge_method", endpoint)
    if self.code_challenge_method not in code_challenge_methods_supported:
      logger.error(f"invalid code_challenge_method {self.code_challenge_method} in `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `code_challenge_method` parameter")

  def validate_response_mode(self, response_modes_supported: list[str], endpoint: str):
    self.response_mode = self.strip(self.response_mode)
    self.check_missing_parameter(self.response_mode, "response_mode", endpoint)
    if self.response_mode not in response_modes_supported:
      logger.error(f"invalid response_mode {self.response_mode} in `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `response_mode` parameter")

  def validate_response_type(self, response_types_supported: list[str], endpoint: str):
    self.response_type = self.strip(self.response_type)
    self.check_missing_parameter(self.response_type, "response_type", endpoint)
    if self.response_type not in response_types_supported:
      logger.error(f"invalid response type {self.response_type} in `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `response_type` parameter")

  def validate_client_id(self, req_client_id: str, endpoint: str):
    self.client_id = self.strip(self.client_id)
    self.check_missing_parameter(self.client_id, "client_id", endpoint)
    if self.client_id != req_client_id:
      logger.error(f"invalid request client_id {self.client_id} in `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `client_id` parameter")

  def validate_state(self, endpoint: str):
    self.state = self.strip(self.state)
    self.check_missing_parameter(self.state, "state", endpoint)
    if len(self.state) < 32 or not self.state.isalnum():
      logger.error(f"invalid state {self.state} in `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `state` parameter")


  def validate_iss(self, req_client_id: str, endpoint: str):
    self.iss = self.strip(self.iss)
    self.check_missing_parameter(self.iss, "iss", endpoint)
    if self.iss != req_client_id:
      logger.error(f"invalid request iss {self.iss} in `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `iss` parameter")

  def validate_aud(self, endpoint: str):
    self.aud = self.strip(self.aud)
    self.check_missing_parameter(self.aud, "aud", endpoint)
    if self.aud != self.get_ctx(ENTITY_ID_CTX):
      logger.error(f"invalid request `aud` {self.aud} in `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `aud` parameter")

  def validate_redirect_uri(self, endpoint: str):
    self.redirect_uri = self.strip(self.redirect_uri)
    self.check_missing_parameter(self.redirect_uri, "redirect_uri", endpoint)

    try:
      parsed_redirect_uri = urlparse(self.redirect_uri)
      if not parsed_redirect_uri.scheme or not parsed_redirect_uri.netloc or not parsed_redirect_uri.path:
        logger.error(f"invalid redirect_uri value '{self.redirect_uri}' in `{endpoint}` endpoint")
        raise InvalidRequestException("invalid `redirect_uri` parameter")
    except Exception as e:
      logger.error(f"invalid redirect_uri value '{self.redirect_uri}' in `{endpoint}` endpoint: {e}")
      raise InvalidRequestException("invalid `redirect_uri` parameter")

  def validate_jti(self, endpoint: str):
    self.jti = self.strip(self.jti)
    self.check_missing_parameter(self.jti, "jti", endpoint)

    if self.iss not in self.jti:
      logger.error(f"invalid jti {self.jti} in request `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `jti` parameter")

    if len(self.jti) - len(self.iss) == 0:
      logger.error(f"invalid jti {self.jti} in request `{endpoint}` endpoint")
      raise InvalidRequestException("invalid `jti` parameter")
