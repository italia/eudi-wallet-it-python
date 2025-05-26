from urllib.parse import urlencode
from uuid import uuid4

from pydantic import BaseModel, Field
from satosa.response import Redirect

from pyeudiw.openid4vci.utils.content_type import FORM_URLENCODED

class AuthorizationResponse(BaseModel):

  code: str = Field(default_factory=lambda: str(uuid4()))
  state: str
  iss: str

  def to_redirect_response(self, url: str) -> Redirect:
    return Redirect(
      f"{url}?{urlencode(self.model_dump())}",
      content = FORM_URLENCODED
    )