import json
import re
from unittest.mock import ANY, patch

import pytest
from satosa.context import Context

from pyeudiw.satosa.frontends.openid4vci.endpoints.nonce_endpoint import NonceHandler
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.tests.satosa.frontends.openid4vci.endpoints.endpoints_test import (
    assert_invalid_request_application_json,
    do_test_invalid_content_type,
    do_test_invalid_request_method,
)
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    INVALID_CONTENT_TYPES_NOT_FORM_URLENCODED,
    INVALID_METHOD_FOR_POST_REQ,
    MOCK_BASE_URL,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    get_mocked_satosa_context,
)
from pyeudiw.tools.content_type import FORM_URLENCODED, HTTP_CONTENT_TYPE_HEADER


@pytest.fixture
def nonce_handler() -> NonceHandler:
    with patch(
        "pyeudiw.satosa.frontends.openid4vci.endpoints.nonce_endpoint.OpenId4VciDBEngineHandler"
    ) as db_handler:
        db_handler.return_value.db_engine.write.return_value = 1
        return NonceHandler(
            MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME
        )


@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(content_type=FORM_URLENCODED)


@pytest.mark.parametrize("method", INVALID_METHOD_FOR_POST_REQ)
def test_invalid_request_method(nonce_handler, context, method):
    do_test_invalid_request_method(nonce_handler, context, method)


@pytest.mark.parametrize("content_type", INVALID_CONTENT_TYPES_NOT_FORM_URLENCODED)
def test_invalid_content_type(nonce_handler, context, content_type):
    context.http_headers[HTTP_CONTENT_TYPE_HEADER] = content_type
    do_test_invalid_content_type(nonce_handler, context, content_type)


@pytest.mark.parametrize(
    "request_nonce",
    [
        {"body": ["is_present"]},
        {"body": "is_present"},
        {"body_is_present"},
        "body_is_present",
    ],
)
def test_invalid_request(nonce_handler, context, request_nonce):
    context.request = request_nonce
    assert_invalid_request_application_json(
        nonce_handler.endpoint(context), "Request body must be empty for nonce endpoint"
    )


def test_valid_request(nonce_handler, context):
    result = nonce_handler.endpoint(context)

    assert result.status == "200 OK"
    response = json.loads(result.message)
    c_nonce = response["c_nonce"]
    assert c_nonce is not None
    assert re.compile(
        r"^[0-9a-f]{8}-"
        r"[0-9a-f]{4}-"
        r"[1-5][0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-"
        r"[0-9a-f]{12}$",
        re.IGNORECASE,
    ).fullmatch(c_nonce)
    nonce_handler.db_engine.write.assert_called_once_with(
        "insert_nonce", nonce=c_nonce, created_at=ANY, expires_in=300
    )


@pytest.mark.parametrize("raises", [False, True])
def test_storage_failure(nonce_handler, context, raises):
    if raises:
        nonce_handler.db_engine.write.side_effect = StorageWriteError("write failed")
    else:
        nonce_handler.db_engine.write.return_value = 0

    result = nonce_handler.endpoint(context)

    assert result.status == "500"
    assert json.loads(result.message)["error"] == "server_error"
