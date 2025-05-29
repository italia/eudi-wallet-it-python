import json
from urllib.parse import urlparse, parse_qs

from satosa.response import BadRequest, Unauthorized, Redirect, ServiceError

from pyeudiw.tools.content_type import APPLICATION_JSON, FORM_URLENCODED, ContentTypeUtils
from pyeudiw.openid4vci.utils.response import ResponseUtils


def test_invalid_scope_response():
    resp = ResponseUtils.to_invalid_scope_resp("Scope not allowed")
    assert isinstance(resp, BadRequest)
    assert ContentTypeUtils.get_content_type_header(resp.headers) == APPLICATION_JSON
    payload = json.loads(resp.message)
    assert payload["error"] == "invalid_scope"
    assert payload["error_description"] == "Scope not allowed"


def test_invalid_request_response():
    resp = ResponseUtils.to_invalid_request_resp("Missing parameter")
    assert isinstance(resp, BadRequest)
    assert ContentTypeUtils.get_content_type_header(resp.headers) == APPLICATION_JSON
    payload = json.loads(resp.message)
    assert payload["error"] == "invalid_request"
    assert payload["error_description"] == "Missing parameter"


def test_invalid_client_response():
    resp = ResponseUtils.to_invalid_client_resp("Unknown client")
    assert isinstance(resp, Unauthorized)
    assert ContentTypeUtils.get_content_type_header(resp.headers) == APPLICATION_JSON
    payload = json.loads(resp.message)
    assert payload["error"] == "invalid_client"
    assert payload["error_description"] == "Unknown client"


def test_server_error_response():
    resp = ResponseUtils.to_server_error_resp("Internal failure")
    assert isinstance(resp, ServiceError)
    assert ContentTypeUtils.get_content_type_header(resp.headers) == APPLICATION_JSON
    payload = json.loads(resp.message)
    assert payload["error"] == "server_error"
    assert payload["error_description"] == "Internal failure"


def test_invalid_request_redirect():
    redirect_url = "https://client.example.com/cb"
    desc = "Missing state"
    state = "xyz123"
    resp = ResponseUtils.to_invalid_request_redirect(redirect_url, desc, state)

    assert isinstance(resp, Redirect)
    assert ContentTypeUtils.get_content_type_header(resp.headers) == FORM_URLENCODED
    parsed = urlparse(resp.message)
    params = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "client.example.com"
    assert parsed.path == "/cb"
    assert params["error"] == ["invalid_request"]
    assert params["error_description"] == [desc]
    assert params["state"] == [state]


def test_server_error_redirect_with_state():
    resp = ResponseUtils.to_server_error_redirect("https://example.com/cb", "unexpected error", "abc987")

    assert isinstance(resp, Redirect)
    assert ContentTypeUtils.get_content_type_header(resp.headers) == FORM_URLENCODED
    parsed = urlparse(resp.message)
    params = parse_qs(parsed.query)

    assert params["error"] == ["server_error"]
    assert params["error_description"] == ["unexpected error"]
    assert params["state"] == ["abc987"]


def test_server_error_redirect_without_state():
    resp = ResponseUtils.to_server_error_redirect("https://example.com/cb", "server is down", None)

    assert isinstance(resp, Redirect)
    assert ContentTypeUtils.get_content_type_header(resp.headers) == FORM_URLENCODED
    parsed = urlparse(resp.message)
    params = parse_qs(parsed.query)

    assert params["error"] == ["server_error"]
    assert params["error_description"] == ["server is down"]
    assert "state" not in params
