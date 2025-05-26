import logging
from typing import Optional

from pydantic import BaseModel, model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException

logger = logging.getLogger(__name__)

AUTHORIZATION_CODE_GRANT = "authorization_code"
REFRESH_TOKEN_GRANT = "refresh_token"

class TokenRequest(BaseModel):
  grant_type: str
  code: str
  redirect_uri: str
  code_verifier: str
  refresh_token: str
  scope: Optional[str]

  @model_validator(mode='after')
  def check_token_request(self) -> "TokenRequest":
    if self.grant_type not in [AUTHORIZATION_CODE_GRANT, REFRESH_TOKEN_GRANT]:
      logger.error(f"Invalid `grant_type` {self.grant_type} in token request")
      raise InvalidRequestException("invalid `grant_type`")

    is_authorization_code_grant =  self.grant_type == AUTHORIZATION_CODE_GRANT
    if is_authorization_code_grant and not self.code:
      logger.error("Missing `code` in token request with authorization_code as `grant_type`")
      raise InvalidRequestException("missing `code`")
    elif not is_authorization_code_grant and self.code:
      logger.error("unexpected `code` for token request with refresh_token as `grant_type`")
      raise InvalidRequestException("unexpected `code`")

    #TODO: check code as returned in authentication response

    if is_authorization_code_grant and not self.redirect_uri:
      logger.error("Missing `redirect_uri` in token request with authorization_code as `grant_type`")
      raise InvalidRequestException("missing `redirect_uri`")
    elif not is_authorization_code_grant and self.redirect_uri:
      logger.error("unexpected `redirect_uri` for token request with refresh_token as `grant_type`")
      raise InvalidRequestException("unexpected `redirect_uri`")

    if is_authorization_code_grant and not self.code_verifier:
      logger.error("Missing `code_verifier` in token request with authorization_code as `grant_type`")
      raise InvalidRequestException("missing `code_verifier`")
    elif not is_authorization_code_grant and self.code_verifier:
      logger.error("unexpected `code_verifier` for token request with refresh_token as `grant_type`")
      raise InvalidRequestException("unexpected `code_verifier`")

    if is_authorization_code_grant and self.refresh_token:
      logger.error("unexpected `refresh_token` for token request with authorization_code as `grant_type`")
      raise InvalidRequestException("unexpected `code_verifier`")
    elif not is_authorization_code_grant and not self.refresh_token:
      logger.error("missing `refresh_token` for token request with refresh_token as `grant_type`")
      raise InvalidRequestException("missing `refresh_token`")

    if is_authorization_code_grant and self.scope:
      logger.error("unexpected `scope` for token request with authorization_code as `grant_type`")
      raise InvalidRequestException("unexpected `scope`")

    return self
