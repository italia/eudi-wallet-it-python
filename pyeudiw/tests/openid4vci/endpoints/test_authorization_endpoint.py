from unittest.mock import Mock

import pytest
from satosa.response import Response

from pyeudiw.openid4vci.endpoints.authorization_endpoint import AuthorizationHandler
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context,
    get_mocked_openid4vpi_entity
)


@pytest.fixture
def authorization_handler() -> AuthorizationHandler:
    handler = AuthorizationHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    handler.db_engine = Mock()
    return handler

@pytest.mark.parametrize("method", [
    "PUT",
    "DELETE"
])
def test_invalid_request_method(authorization_handler, method):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    _assert_invalid_request(
        authorization_handler.endpoint(get_mocked_satosa_context(method=method)),
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
    "application/soap+xml",
    "application/json"
])
def test_invalid_content_type_for_POST_method(authorization_handler, content_type):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    _assert_invalid_request(
        authorization_handler.endpoint(get_mocked_satosa_context(
            method="POST",
            content_type=content_type
        )),
        "invalid content-type"
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
    "application/soap+xml",
    "application/x-www-form-urlencoded"
])
def test_invalid_content_type_for_GET_method(authorization_handler, content_type):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    _assert_invalid_request(
        authorization_handler.endpoint(get_mocked_satosa_context(
            method="GET",
            content_type=content_type
        )),
        "invalid content-type"
    )

def _assert_invalid_request(result: Response, error_desc: str):
    assert result.status == '302 Found'
    assert result.message == (f'https://client.com?error=invalid_request'
                              f'&error_description={error_desc.replace(" ", "+")}'
                              f'&state=xyz456')
