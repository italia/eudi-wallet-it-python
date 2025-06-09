import json
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qs

import pytest
from satosa.context import Context
from satosa.response import Response

from pyeudiw.openid4vci.endpoints.authorization_endpoint import AuthorizationHandler
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context,
    get_mocked_openid4vpi_entity,
    get_pyeudiw_frontend_config_with_openid_credential_issuer
)
from pyeudiw.tools.content_type import APPLICATION_JSON, HTTP_CONTENT_TYPE_HEADER
from pyeudiw.tools.validation import is_valid_uuid


@pytest.fixture
def authorization_handler() -> AuthorizationHandler:
    handler = AuthorizationHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    handler.db_engine = Mock()
    return handler

@pytest.fixture()
def context() -> Context:
    return get_mocked_satosa_context()

@pytest.mark.parametrize("method", [
    "PUT",
    "DELETE"
])
def test_invalid_request_method(authorization_handler, context, method):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    context.request_method = method
    _assert_invalid_request(
        authorization_handler.endpoint(context),
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
def test_invalid_content_type_for_POST_method(authorization_handler, context, content_type):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    context.http_headers[HTTP_CONTENT_TYPE_HEADER] = content_type
    _assert_invalid_request(
        authorization_handler.endpoint(context),
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
def test_invalid_content_type_for_GET_method(authorization_handler, context, content_type):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    context.request_method = "GET"
    context.http_headers[HTTP_CONTENT_TYPE_HEADER] = content_type
    _assert_invalid_request(
        authorization_handler.endpoint(context),
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
def test_invalid_authorization_request_in_POST(authorization_handler, context, req, err_descr: str):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    context.request = json.dumps(req)
    _assert_invalid_request(
        authorization_handler.endpoint(context),
        err_descr
    )

@pytest.mark.parametrize("client_id,request_uri,,err_descr", [
    ("", "", "missing authorization request"),
    ("", None, "missing authorization request"),
    (None, "", "missing authorization request"),
    (None, None,  "missing authorization request"),
    ("", None,  "missing authorization request"),
    (None, "",  "missing authorization request"),
    (" ", " ", "missing `client_id` parameter"),
    ("client123", " ", "missing `request_uri` parameter"),
    ("123", "urn:ietf:params:oauth:request_uri:request_uri_part", "invalid `client_id` parameter"),
    ("client123", "request_uri_part", "invalid `request_uri` parameter"),
])
def test_invalid_authorization_request_in_GET(authorization_handler, context, client_id, request_uri, err_descr: str):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    _get_context(context)
    qs_params = {}
    if client_id:
        qs_params.update({"client_id" : client_id})
    if request_uri:
        qs_params.update({"request_uri" : request_uri})
    context.qs_params = qs_params
    _assert_invalid_request(
        authorization_handler.endpoint(context),
        err_descr
    )

def test_valid_authorization_request_in_GET(authorization_handler, context):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    _get_context(context)
    context.qs_params = {
        "client_id" : "client123",
        "request_uri" : "urn:ietf:params:oauth:request_uri:request_uri_part"
    }
    _assert_response(
        authorization_handler.endpoint(context),
        'example.com/openid4vcimock'
    )

def test_valid_authorization_request_in_GET_with_credential_issuer(context):
    config = get_pyeudiw_frontend_config_with_openid_credential_issuer("https://example.com/issuer")
    authorization_handler = AuthorizationHandler(config, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    authorization_handler.db_engine = Mock()
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    _get_context(context)
    context.qs_params = {
        "client_id" : "client123",
        "request_uri" : "urn:ietf:params:oauth:request_uri:request_uri_part"
    }
    _assert_response(
        authorization_handler.endpoint(context),
        "https://example.com/issuer"
    )

def test_valid_authorization_request_in_POST(authorization_handler, context):
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    context.request = {
        "client_id" : "client123",
        "request_uri" : "urn:ietf:params:oauth:request_uri:request_uri_part"
    }
    _assert_response(
        authorization_handler.endpoint(context),
        'example.com/openid4vcimock'
    )

def test_valid_authorization_request_in__with_credential_issuer(context):
    config = get_pyeudiw_frontend_config_with_openid_credential_issuer("https://example.com/issuer")
    authorization_handler = AuthorizationHandler(config, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    authorization_handler.db_engine = Mock()
    authorization_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    context.request = {
        "client_id" : "client123",
        "request_uri" : "urn:ietf:params:oauth:request_uri:request_uri_part"
    }
    _assert_response(
        authorization_handler.endpoint(context),
        "https://example.com/issuer"
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

def _assert_response(result: Response, issuer: str):
    assert result.status == '302 Found'
    result_message_url = urlparse(result.message)
    assert result_message_url.scheme == "https"
    assert result_message_url.hostname == "client.com"

    actual_params = parse_qs(result_message_url.query)
    assert 'code' in actual_params
    assert True == is_valid_uuid(actual_params['code'][0])

    assert 'iss' in actual_params
    assert actual_params['iss'] == [issuer]

    assert 'state' in actual_params
    assert actual_params['state'] == ['xyz456']

def _get_context(context: Context):
    context.request_method = "GET"
    context.http_headers[HTTP_CONTENT_TYPE_HEADER] = APPLICATION_JSON