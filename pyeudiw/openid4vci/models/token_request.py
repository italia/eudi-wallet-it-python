import logging
from hashlib import sha256, sha512
from typing import Optional

from pydantic import model_validator

from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel
from pyeudiw.openid4vci.tools.exceptions import InvalidRequestException

logger = logging.getLogger(__name__)

AUTHORIZATION_CODE_GRANT = "authorization_code"
REFRESH_TOKEN_GRANT = "refresh_token" # nosec B105

REDIRECT_URI_CTX = "redirect_uri"
CODE_CHALLENGE_METHOD_CTX = "code_challenge_method"
CODE_CHALLENGE_CTX = "code_challenge"
SCOPE_CTX = "scope"

TOKEN_ENDPOINT = "token" # nosec B105

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
  grant_type: str = None
  code: Optional[str] = None
  redirect_uri: Optional[str] = None
  code_verifier: Optional[str] = None
  refresh_token: Optional[str] = None
  scope: Optional[str] = None

  @model_validator(mode='after')
  def check_token_request(self) -> "TokenRequest":
    self.validate_grant_type()
    is_authorization_code_grant =  self.grant_type == AUTHORIZATION_CODE_GRANT
    self.validate_code(is_authorization_code_grant)
    self.validate_redirect_uri(is_authorization_code_grant)
    self.validate_code_verifier(is_authorization_code_grant)
    self.validate_refresh_token(is_authorization_code_grant)
    self.validate_scope(is_authorization_code_grant)
    return self

  def validate_scope(self, is_authorization_code_grant):
    self.scope = self.strip(self.scope)
    if is_authorization_code_grant:
      self.check_unexpected_parameter(self.scope, "scope", TOKEN_ENDPOINT)
    elif self.scope:
      scopes = self.scope.split(" ")
      par_scope_ctx = self.get_ctx(SCOPE_CTX)
      par_scopes = par_scope_ctx.split(" ") if par_scope_ctx is not None else None
      for s in scopes:
        if s not in self.get_config().metadata.oauth_authorization_server.scopes_supported:
          logger.error(f"invalid scope value '{s}' in `token` endpoint")
          raise InvalidRequestException(f"invalid scope value '{s}'")
        elif par_scopes and (s not in par_scopes):
          logger.error(f"invalid scope in `token` endpoint: value '{s}' not present in previous `par` endpoint")
          raise InvalidRequestException(f"invalid scope value '{s}'")

  def validate_refresh_token(self, is_authorization_code_grant):
    self.refresh_token = self.strip(self.refresh_token)
    if is_authorization_code_grant:
      self.check_unexpected_parameter(self.refresh_token, "refresh_token", TOKEN_ENDPOINT)
    else:
      self.check_missing_parameter(self.refresh_token, "refresh_token", TOKEN_ENDPOINT)

  def validate_code_verifier(self, is_authorization_code_grant):
    self.code_verifier = self.strip(self.code_verifier)
    if is_authorization_code_grant:
      self.check_missing_parameter(self.code_verifier, "code_verifier", TOKEN_ENDPOINT)

      match self.get_ctx(CODE_CHALLENGE_METHOD_CTX).upper():
        case "S256":
          code_verifier_encode = sha256(self.code_verifier.encode('utf-8')).hexdigest()
        case "S512":
          code_verifier_encode = sha512(self.code_verifier.encode('utf-8')).hexdigest()
        case _:
          logger.error(
            f"unexpected code_challenge_method {self.get_ctx(CODE_CHALLENGE_METHOD_CTX)} for code_verifier in token request")
          raise InvalidRequestException("Invalid `code_verifier`")

      if code_verifier_encode != self.get_ctx(CODE_CHALLENGE_CTX):
        logger.error(
          f"Invalid `code_verifier` {code_verifier_encode} in token request with authorization_code as `grant_type`")
        raise InvalidRequestException("Invalid `code_verifier`")
    else:
      self.check_unexpected_parameter(self.code_verifier, "code_verifier", TOKEN_ENDPOINT)

  def validate_redirect_uri(self, is_authorization_code_grant):
    self.redirect_uri = self.strip(self.redirect_uri)
    if is_authorization_code_grant:
      self.check_missing_parameter(self.redirect_uri, "redirect_uri", TOKEN_ENDPOINT)
      if self.get_ctx(REDIRECT_URI_CTX) != self.redirect_uri:
        logger.error("Invalid `redirect_uri` in token request with authorization_code as `grant_type`")
        raise InvalidRequestException("Invalid `redirect_uri`")
    else:
      self.check_unexpected_parameter(self.redirect_uri, "redirect_uri", TOKEN_ENDPOINT)

  def validate_grant_type(self):
    self.grant_type = self.strip(self.grant_type)
    self.check_missing_parameter(self.grant_type, "grant_type", TOKEN_ENDPOINT)
    if self.grant_type not in [AUTHORIZATION_CODE_GRANT, REFRESH_TOKEN_GRANT]:
      logger.error(f"Invalid `grant_type` {self.grant_type} in token request")
      raise InvalidRequestException("invalid `grant_type`")

  def validate_code(self, is_authorization_code_grant: bool):
    self.code = self.strip(self.code)
    if is_authorization_code_grant:
      self.check_missing_parameter(self.code, "code", TOKEN_ENDPOINT)
    else:
      self.check_unexpected_parameter(self.code, "code", TOKEN_ENDPOINT)

