from typing import List

from pydantic import BaseModel
from satosa.response import Created

from pyeudiw.openid4vci.models.auhtorization_detail import AuthorizationDetail
from pyeudiw.openid4vci.utils.content_type import APPLICATION_JSON


class TokenResponse(BaseModel):
  """
  Pydantic model representing the response returned from the token endpoint.

  Attributes:
      access_token (str): The access token issued by the authorization server.
      refresh_token (str): The refresh token that can be used to obtain new access tokens.
      token_type (str): The type of the token issued (e.g., 'Bearer').
      expires_in (int): The lifetime in seconds of the access token.
      authorization_details (List of AuthorizationDetail): Details about the granted authorization.
  """
  access_token: str
  refresh_token: str
  token_type: str
  expires_in: int
  authorization_details: List[AuthorizationDetail] = None

  @staticmethod
  def to_created_response(access_token: str, refresh_token: str, expires_in: int, authorization_details: List[AuthorizationDetail]) -> Created:
    """
    Converts the token response to a `Created` HTTP response object.
    Returns:
        Created: An HTTP 201 Created response containing the JSON-serialized token response.
    """
    data = TokenResponse(
      access_token=access_token,
      refresh_token=refresh_token,
      token_type="DPOP", # nosec B106
      expires_in=expires_in,
      authorization_details=authorization_details
    )
    return Created(
      message=data.model_dump_json(),
      content=APPLICATION_JSON,
    )
