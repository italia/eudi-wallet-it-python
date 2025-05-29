from urllib.parse import urlencode
from uuid import uuid4

from pydantic import BaseModel, Field
from satosa.response import Redirect

from pyeudiw.tools.content_type import FORM_URLENCODED


class AuthorizationResponse(BaseModel):
  """
  Represents an authorization response containing code, state, and issuer.

  Attributes:
      code (str): The authorization code to return. If not provided, a random UUID is used.
  """

  code: str = Field(default_factory=lambda: str(uuid4()))
  state: str
  iss: str

  def to_redirect_response(self, url: str) -> Redirect:
    """
    Constructs a SATOSA Redirect response by encoding the current AuthorizationResponse
    fields as query parameters and appending them to the provided base URL.

    Args:
        url (str): The base redirect URI.

    Returns:
        Redirect: A SATOSA Redirect object containing the full redirect URI with parameters.
    """
    return Redirect(
      f"{url}?{urlencode(self.model_dump())}",
      content=FORM_URLENCODED
    )
