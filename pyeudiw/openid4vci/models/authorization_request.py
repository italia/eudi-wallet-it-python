import logging

from pydantic import BaseModel, model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import \
  InvalidRequestException

logger = logging.getLogger(__name__)

class AuthorizationRequest(BaseModel):
  client_id: str
  request_uri: str

  @model_validator(mode='after')
  def check_authorization_request(self) -> "AuthorizationRequest":
    if not self.client_id:
      logger.error("missing `client_id` in request `authorization` endpoint")
      raise InvalidRequestException("missing `client_id` parameter")

    if not self.request_uri:
      logger.error("missing `request_uri` in request `authorization` endpoint")
      raise InvalidRequestException("missing `request_uri` parameter")

    par_request_uri = (self.__pydantic_context__.get("par_obj", {})
              .get("request_uri"))
    if par_request_uri != self.request_uri:
      logger.error("Invalid `request_uri` in request `authorization` endpoint")
      raise InvalidRequestException("invalid `request_uri` parameter")
