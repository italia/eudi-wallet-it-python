from urllib.parse import urlparse, parse_qs
from uuid import uuid4

from satosa.response import Redirect

from pyeudiw.openid4vci.models.authorization_response import AuthorizationResponse
from pyeudiw.tools.content_type import (
  FORM_URLENCODED,
  get_content_type_header
)


def test_to_redirect_response_without_code():

  response_data = AuthorizationResponse(
    state="mystate",
    iss="myiss"
  )

  response = response_data.to_redirect_response("https://test.url")

  assert isinstance(response, Redirect)
  assert get_content_type_header(response.headers) == FORM_URLENCODED
  redirect_url = urlparse(response.message)
  query = parse_qs(redirect_url.query)
  assert query.get("state", [None])[0] == "mystate"
  assert query.get("iss", [None])[0] == "myiss"
  assert query.get("code", [None])[0] is not None
  assert (redirect_url.scheme + "://" + redirect_url.hostname) == "https://test.url"

def test_to_redirect_response_with_code():
  code = str(uuid4())
  response_data = AuthorizationResponse(
    state="mystate",
    iss="myiss",
    code=code
  )

  response = response_data.to_redirect_response("https://test.url")

  assert isinstance(response, Redirect)
  assert get_content_type_header(response.headers) == FORM_URLENCODED
  redirect_url = urlparse(response.message)
  query = parse_qs(redirect_url.query)
  assert query.get("state", [None])[0] == "mystate"
  assert query.get("iss", [None])[0] == "myiss"
  assert query.get("code", [None])[0] == code
  assert (redirect_url.scheme + "://" + redirect_url.hostname) == "https://test.url"

