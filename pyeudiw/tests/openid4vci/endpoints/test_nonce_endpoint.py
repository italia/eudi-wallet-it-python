import json
import re
from unittest.mock import MagicMock

import pytest
from satosa.context import Context

from pyeudiw.openid4vci.endpoints.nonce_endpoint import NonceHandler
from pyeudiw.tests.openid4vci.endpoints.endpoints_test import (
    do_test_invalid_request_method,
    do_test_invalid_content_type,
    assert_invalid_request_application_json
)
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    INVALID_METHOD_FOR_POST_REQ,
    INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_BASE_URL,
    MOCK_NAME,
    get_mocked_satosa_context,
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON
)


@pytest.fixture
def nonce_handler() -> NonceHandler:
    return NonceHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(content_type = APPLICATION_JSON)


@pytest.mark.parametrize("method", INVALID_METHOD_FOR_POST_REQ)
def test_invalid_request_method(nonce_handler, context, method):
    do_test_invalid_request_method(nonce_handler,context, method)

@pytest.mark.parametrize("content_type", INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON)
def test_invalid_content_type(nonce_handler, context, content_type):
    context.http_headers[HTTP_CONTENT_TYPE_HEADER] = content_type
    do_test_invalid_content_type(nonce_handler, context, content_type)

@pytest.mark.parametrize("request_nonce", [
    {"body":["is_present"]},
    {"body": "is_present"},
    {"body_is_present"},
    "body_is_present"
])
def test_invalid_request(nonce_handler, context, request_nonce):
    context.request = request_nonce
    assert_invalid_request_application_json(
        nonce_handler.endpoint(context),
        "Request body must be empty for nonce endpoint"
    )


def test_valid_request(nonce_handler, context):
    nonce_handler.db_engine = MagicMock()
    result = nonce_handler.endpoint(context)

    assert result.status == '200 OK'
    response = json.loads(result.message)
    c_nonce = response["c_nonce"]
    assert c_nonce is not None
    assert re.compile(
        r"^[0-9a-f]{8}-"
        r"[0-9a-f]{4}-"
        r"[1-5][0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-"
        r"[0-9a-f]{12}$",
        re.IGNORECASE
    ).fullmatch(c_nonce)
