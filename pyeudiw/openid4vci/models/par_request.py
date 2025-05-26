import logging
from typing import List

from pydantic import BaseModel, model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException
from pyeudiw.openid4vci.utils.date import DateUtils

logger = logging.getLogger(__name__)

class AuthorizationDetail(BaseModel):
  type: str
  credential_configuration_id: str  # JsonStr

class ParRequest(BaseModel):
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
    config = (self.__pydantic_context__.get("config", {})
              .get("metadata", {}).get("oauth_authorization_server", {}))

    if not self.iss:
      logger.error("missing iss in request `par` endpoint")
      raise InvalidRequestException("missing `iss` parameter")

    if not self.aud:
      logger.error("missing aud in request `par` endpoint")
      raise InvalidRequestException("missing `aud` parameter")

    if not DateUtils.is_valid_unix_timestamp(self.exp):
      logger.error(f"invalid exp {self.exp} in request `par` endpoint")
      raise InvalidRequestException("invalid `exp` parameter")

    if not DateUtils.is_valid_unix_timestamp(self.iat):
      logger.error(f"invalid iat {self.iat} in request `par` endpoint")
      raise InvalidRequestException("invalid `iat` parameter")

    if int(self.exp) - int(self.iat) > 300:
      logger.error("expired request token in `par` endpoint")
      raise InvalidRequestException("expired token")

    if self.response_type not in config.get("response_types_supported", []):
      logger.error(f"invalid response type {self.response_type} in `par` endpoint")
      raise InvalidRequestException("invalid `response_type` parameter")

    if self.response_mode not in config.get("response_modes_supported", []):
      logger.error(f"invalid response_mode {self.response_mode} in `par` endpoint")
      raise InvalidRequestException("invalid `response_mode` parameter")

    if self.client_id != self.__pydantic_context__.get("client_id"):
      logger.error(f"invalid request client_id {self.client_id} in `par` endpoint")
      raise InvalidRequestException("invalid `request.client_id` parameter")

    if len(self.state) < 32 or not self.state.isalnum():
      logger.error(f"invalid state {self.state} in `par` endpoint")
      raise InvalidRequestException("invalid `state` parameter")

    if not self.code_challenge:
      logger.error("missing `code_challenge` in `par` endpoint request")
      raise InvalidRequestException("missing `code_challenge` parameter")

    if self.code_challenge_method not in config.get("code_challenge_methods_supported", []):
      logger.error(f"invalid code_challenge_method {self.code_challenge_method} in `par` endpoint")
      raise InvalidRequestException("invalid `code_challenge_method` parameter")

    scopes = self.scope.split(" ")
    supported_scopes = config.get("scopes_supported", [])
    for s in scopes:
      if s not in supported_scopes:
        logger.error(f"invalid scope value '{s}' in `par` endpoint")
        raise InvalidRequestException(f"invalid scope value '{s}'")

    return self
