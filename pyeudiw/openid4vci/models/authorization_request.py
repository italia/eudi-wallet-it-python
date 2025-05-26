import logging

from pydantic import model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException
from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel, CLIENT_ID_CTX

logger = logging.getLogger(__name__)

PAR_REQUEST_URI_CTX = "par_request_uri"

class AuthorizationRequest(OpenId4VciBaseModel):
  client_id: str
  request_uri: str

  @model_validator(mode='after')
  def check_authorization_request(self) -> "AuthorizationRequest":
    if not self.client_id:
      logger.error("missing `client_id` in request `authorization` endpoint")
      raise InvalidRequestException("missing `client_id` parameter")

    if self.client_id != self.get_ctx(CLIENT_ID_CTX):
      logger.error(f"invalid request `client_id` {self.client_id} in `authorization` endpoint")
      raise InvalidRequestException("invalid `client_id` parameter")

    if not self.request_uri:
      logger.error("missing `request_uri` in request `authorization` endpoint")
      raise InvalidRequestException("missing `request_uri` parameter")

    if self.get_ctx(PAR_REQUEST_URI_CTX) != self.request_uri:
      logger.error("Invalid `request_uri` in request `authorization` endpoint")
      raise InvalidRequestException("invalid `request_uri` parameter")

    return self
