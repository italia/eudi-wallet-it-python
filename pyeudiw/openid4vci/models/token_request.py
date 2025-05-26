import logging
from hashlib import sha256, sha512
from typing import Optional

from pydantic import model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException
from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel

logger = logging.getLogger(__name__)

AUTHORIZATION_CODE_GRANT = "authorization_code"
REFRESH_TOKEN_GRANT = "refresh_token"

REDIRECT_URI_CTX = "redirect_uri"
CODE_CHALLENGE_METHOD_CTX = "code_challenge_method"
CODE_CHALLENGE_CTX = "code_challenge"

class TokenRequest(OpenId4VciBaseModel):
  """
  Represents a request to the token endpoint in an OpenID4VCI flow.

  Fields:
      grant_type (str): Either 'authorization_code' or 'refresh_token'.
      code (str): Required for 'authorization_code' grant type.
      redirect_uri (str): Required for 'authorization_code' grant type.
      code_verifier (str): Required for PKCE validation.
      refresh_token (str): Required for 'refresh_token' grant type.
      scope (Optional[str]): Optional, only valid for 'refresh_token'.

  Validation Logic:
      - Validates `grant_type` is one of the supported values.
      - Enforces required fields depending on the grant type.
      - Validates PKCE `code_verifier` against the challenge using SHA256 or SHA512.
      - Ensures `scope` values are in the allowed configuration list.
      - Raises `InvalidRequestException` with appropriate messages if checks fail.
  """
  grant_type: str
  code: Optional[str] = None
  redirect_uri: Optional[str] = None
  code_verifier: Optional[str] = None
  refresh_token: Optional[str] = None
  scope: Optional[str] = None

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

    if is_authorization_code_grant:
      if not self.redirect_uri:
        logger.error("Missing `redirect_uri` in token request with authorization_code as `grant_type`")
        raise InvalidRequestException("missing `redirect_uri`")
      elif self.get_ctx(REDIRECT_URI_CTX) != self.redirect_uri:
        logger.error("Invalid `redirect_uri` in token request with authorization_code as `grant_type`")
        raise InvalidRequestException("Invalid `redirect_uri`")
    elif not is_authorization_code_grant and self.redirect_uri:
      logger.error("unexpected `redirect_uri` for token request with refresh_token as `grant_type`")
      raise InvalidRequestException("unexpected `redirect_uri`")

    if is_authorization_code_grant:
      if not self.code_verifier:
        logger.error("Missing `code_verifier` in token request with authorization_code as `grant_type`")
        raise InvalidRequestException("missing `code_verifier`")

      match self.get_ctx(CODE_CHALLENGE_METHOD_CTX):
        case "s256":
          code_verifier_encode = sha256(self.code_verifier.encode('utf-8')).hexdigest()
        case "s512":
          code_verifier_encode = sha512(self.code_verifier.encode('utf-8')).hexdigest()
        case _:
          logger.error(f"unexpected code_challenge_method {self.get_ctx(CODE_CHALLENGE_METHOD_CTX)} for code_verifier in token request")
          raise InvalidRequestException("Invalid `code_verifier`")

      if code_verifier_encode != self.get_ctx(CODE_CHALLENGE_CTX):
        logger.error(f"Invalid `code_verifier` {code_verifier_encode} in token request with authorization_code as `grant_type`")
        raise InvalidRequestException("Invalid `code_verifier`")

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
    elif self.scope:
      scopes = self.scope.split(" ")
      for s in scopes:
        if s not in self.get_config().metadata.oauth_authorization_server.scopes_supported:
          logger.error(f"invalid scope value '{s}' in `authorization` endpoint")
          raise InvalidRequestException(f"invalid scope value '{s}'")

    return self
