import logging

from pydantic import model_validator

from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import (
  OpenId4VciBaseModel,
  CLIENT_ID_CTX,
  ENDPOINT_CTX
)
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidRequestException

logger = logging.getLogger(__name__)

PAR_REQUEST_URI_CTX = "par_request_uri"

class AuthorizationRequest(OpenId4VciBaseModel):
  """
  Represents an authorization request in the OpenID4VCI flow.

  Attributes:
      client_id (str): The client identifier making the authorization request.
      request_uri (str): The URI referencing the request object.

  Validation rules:
      - `client_id` must be present and must match the client_id from the context.
      - `request_uri` must be present and must match the `par_request_uri` value from the context.

  Raises:
      InvalidRequestException: If any of the validation rules fail, with an appropriate error message.
  """

  client_id: str = None
  request_uri: str = None

  @model_validator(mode='after')
  def check_authorization_request(self) -> "AuthorizationRequest":
    endpoint = self.get_ctx(ENDPOINT_CTX)
    self.validate_client_id(endpoint)
    self.validate_request_uri(endpoint)
    return self

  def validate_client_id(self, endpoint: str):
    self.client_id = self.strip(self.client_id)
    self.check_missing_parameter(self.client_id, "client_id", endpoint)
    if self.client_id != self.get_ctx(CLIENT_ID_CTX):
      logger.error(f"invalid request `client_id` {self.client_id} in `authorization` endpoint")
      raise InvalidRequestException("invalid `client_id` parameter")

  def validate_request_uri(self, endpoint: str):
    self.request_uri = self.strip(self.request_uri)
    self.check_missing_parameter(self.request_uri, "request_uri", endpoint)
    if self.get_ctx(PAR_REQUEST_URI_CTX) != self.request_uri:
      logger.error("Invalid `request_uri` in request `authorization` endpoint")
      raise InvalidRequestException("invalid `request_uri` parameter")
