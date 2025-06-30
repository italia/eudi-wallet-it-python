from uuid import uuid4

from pydantic import BaseModel, Field
from satosa.response import Response

from pyeudiw.tools.content_type import (
  APPLICATION_JSON,
  CACHE_CONTROL_HEADER
)


class NonceResponse(BaseModel):
  """
  Pydantic model representing a Nonce Response as defined in OpenID4VCI specification (Section 7.2).

  The response MUST be uncacheable (Cache-Control: no-store) and MUST contain an unpredictable 'c_nonce' value.
  """

  c_nonce: str = Field(default_factory=lambda: str(uuid4()))

  @staticmethod
  def to_response(c_nonce: str = None) -> Response:
    """
    Create a SATOSA Response with a JSON payload containing a c_nonce.

    Args:
        c_nonce (str, optional): Custom nonce value to use. If not provided, a UUID4 will be generated.

    Returns:
        Response: A SATOSA Response object with application/json content and 'Cache-Control: no-store' header.
    """
    data = NonceResponse(c_nonce=c_nonce) if c_nonce else NonceResponse()
    response = Response(
      message=data.model_dump_json(),
      content=APPLICATION_JSON,
    )
    response.headers.append((CACHE_CONTROL_HEADER, "no-store"))
    return response
