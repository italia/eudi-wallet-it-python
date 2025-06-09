from unittest.mock import Mock

import pytest
from satosa.context import Context
from satosa.response import Response

from pyeudiw.openid4vci.endpoints.token_endpoint import TokenHandler
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    INVALID_ATTESTATION_HEADERS,
    get_mocked_satosa_context
)
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, FORM_URLENCODED
from pyeudiw.tools.validation import (
    OAUTH_CLIENT_ATTESTATION_POP_HEADER
)


@pytest.fixture
def token_handler() -> TokenHandler:
    handler = TokenHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    handler.db_engine = Mock()
    return handler

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context()

@pytest.mark.parametrize("method", [
    "GET",
    "PUT",
    "DELETE"
])
def test_invalid_request_method(token_handler, context, method):
    context.request_method = method
    _assert_invalid_request(
        token_handler.endpoint(context),
        "invalid request method"
    )

@pytest.mark.parametrize("content_type", [
    "content_type",
    "multipart/form-data",
    "text/plain",
    "application/xml",
    "application/octet-stream",
    "application/ld+json",
    "text/html",
    "application/jose",
    "application/jwt",
    "application/soap+xml"
])
def test_invalid_content_type(token_handler, context, content_type):
    context.http_headers[HTTP_CONTENT_TYPE_HEADER] = content_type
    _assert_invalid_request(
        token_handler.endpoint(context),
        "invalid content-type"
    )


@pytest.mark.parametrize("headers", INVALID_ATTESTATION_HEADERS)
def test_invalid_oauth_client_attestation(token_handler, headers):
    headers[HTTP_CONTENT_TYPE_HEADER] = FORM_URLENCODED
    _assert_invalid_request(
        token_handler.endpoint(get_mocked_satosa_context(headers=headers)),
        "Missing Wallet Attestation JWT header"
    )

@pytest.mark.parametrize("pop", [
    "valid-pop",
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJub3QtcmVhbCIsImV4cCI6MTY4MDAwMDAwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
])
def test_invalid_jwt_oauth_client_attestation_pop(token_handler, context, pop):
    context.http_headers[OAUTH_CLIENT_ATTESTATION_POP_HEADER] = pop
    _assert_invalid_request(
        token_handler.endpoint(context),
        "Not a valid JWS format"
    )

def _assert_invalid_request(result: Response, error_desc: str):
    assert result.status == '400'
    assert result.message == f'{{"error": "invalid_request", "error_description": "{error_desc}"}}'
