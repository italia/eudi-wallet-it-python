from pydantic import BaseModel
from satosa.response import Created

from pyeudiw.tools.content_type import APPLICATION_JSON


class ParResponse(BaseModel):
  """
  Pydantic model representing the response returned from the Pushed Authorization Request (PAR) endpoint.

  Attributes:
      request_uri (str): The URI that represents the pushed request object.
      expires_in (int): Time in seconds after which the request URI expires.
  """

  request_uri: str
  expires_in: int

  @staticmethod
  def to_created_response(request_uri: str, expires_in: int) -> Created:
    """
    Builds a `Created` response from the given request_uri and expires_in.

    Args:
        request_uri (str): The URI to be returned to the Wallet instance.
        expires_in (int): The validity duration in seconds for the request URI.

    Returns:
        Created: A SATOSA `Created` response with JSON content type and the serialized PAR response payload.
    """
    data = ParResponse(
      request_uri=request_uri,
      expires_in=expires_in
    )
    return Created(
      message=data.model_dump_json(),
      content=APPLICATION_JSON,
    )
