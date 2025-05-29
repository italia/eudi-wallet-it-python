import json
import re

from pyeudiw.openid4vci.models.nonce_response import NonceResponse
from pyeudiw.tools.content_type import APPLICATION_JSON, ContentTypeUtils, CACHE_CONTROL_HEADER


def test_nonce_response_default():
    response = NonceResponse.to_response()
    body = json.loads(response.message)

    assert "c_nonce" in body
    assert re.fullmatch(r"[0-9a-f\-]{36}", body["c_nonce"])  # UUID v4 pattern
    assert ContentTypeUtils.get_content_type_header(response.headers) == APPLICATION_JSON
    assert (CACHE_CONTROL_HEADER, "no-store") in response.headers


def test_nonce_response_with_custom_nonce():
    custom_nonce = "my-custom-nonce"
    response = NonceResponse.to_response(c_nonce=custom_nonce)
    body = json.loads(response.message)

    assert body["c_nonce"] == custom_nonce
    assert ContentTypeUtils.get_content_type_header(response.headers) == APPLICATION_JSON
    assert (CACHE_CONTROL_HEADER, "no-store") in response.headers
