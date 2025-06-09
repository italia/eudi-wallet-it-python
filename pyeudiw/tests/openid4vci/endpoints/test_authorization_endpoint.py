import json
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qs

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

@pytest.mark.parametrize("req,err_descr", [
    ({}, "missing authorization request"),
    ({"client_id": "", "request_uri": ""}, "missing `client_id` parameter"),
    ({"client_id": " ", "request_uri": " "}, "missing `client_id` parameter"),
    ({"client_id": None, "request_uri": None}, "invalid `client_id` parameter"),
    ({"client_id": "", "request_uri": None}, "invalid `request_uri` parameter"),
    ({"client_id": None, "request_uri": ""}, "invalid `client_id` parameter"),
    ({"client_id": "client123", "request_uri": " "}, "missing `request_uri` parameter"),
    ({"client_id": "123", "request_uri": "urn:ietf:params:oauth:request_uri:request_uri_part"}, "invalid `client_id` parameter"),
    ({"client_id": "client123", "request_uri": "request_uri_part"}, "invalid `request_uri` parameter"),
])
def test_invalid_authorization_request_in_POST(authorization_handler, req, err_descr: str):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    context = get_mocked_satosa_context()
    context.request = json.dumps(req)
    _assert_invalid_request(
        authorization_handler.endpoint(context),
        err_descr
    )

def _assert_invalid_request(result: Response, error_desc: str):
    assert result.status == '302 Found'
    result_message_url = urlparse(result.message)
    actual_params = parse_qs(result_message_url.query)
    assert 'error' in actual_params
    assert actual_params['error'] == ['invalid_request']

    assert 'error_description' in actual_params
    assert actual_params['error_description'] == [error_desc]

    assert 'state' in actual_params
    assert actual_params['state'] == ['xyz456']
