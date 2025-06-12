import json
from copy import deepcopy
from unittest.mock import Mock, MagicMock

import pytest
from satosa.context import Context
from satosa.response import Response

from pyeudiw.openid4vci.endpoints.token_endpoint import (
    TokenHandler,
    ACCESS_TOKEN_TYP,
    REFRESH_TOKEN_TYP
)
from pyeudiw.openid4vci.models.token_request import (
    AUTHORIZATION_CODE_GRANT,
    REFRESH_TOKEN_GRANT
)
from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    INVALID_ATTESTATION_HEADERS,
    INVALID_METHOD_FOR_POST_REQ,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context,
    get_mocked_openid4vpi_entity
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    FORM_URLENCODED
)
from pyeudiw.tools.validation import (
    OAUTH_CLIENT_ATTESTATION_POP_HEADER
)


def mock_sign(*args, **kwargs):
    typ = kwargs.get("protected", {}).get("typ")
    if typ == ACCESS_TOKEN_TYP:
        return "fake.access.token"
    elif typ == REFRESH_TOKEN_TYP:
        return "fake.refresh.token"
    else:
        return "unknown.typ.token"

@pytest.fixture
def valid_request_authorization_code():
    return {
        "grant_type": AUTHORIZATION_CODE_GRANT,
        "code": "abc123",
        "redirect_uri": "https://client.com",
        "code_verifier": "code_verifier",
    }

@pytest.fixture
def valid_request_refresh_token():
    return {
        "grant_type": REFRESH_TOKEN_GRANT,
        "refresh_token": "refresh_token",
        "scope": "scope2 openid"
    }

@pytest.fixture
def token_handler() -> TokenHandler:
    handler = TokenHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    handler.db_engine = Mock()
    return handler

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context()

@pytest.mark.parametrize("method", INVALID_METHOD_FOR_POST_REQ)
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
    contx = deepcopy(context)
    contx.http_headers[OAUTH_CLIENT_ATTESTATION_POP_HEADER] = pop
    _assert_invalid_request(
        token_handler.endpoint(contx),
        "Not a valid JWS format"
    )

@pytest.mark.parametrize("value,err_descr", [
    ("" , "missing `grant_type` parameter"),
    (None , "invalid `grant_type` parameter"),
    ("test", "invalid `grant_type`"),
    ("test ", "invalid `grant_type`"),
    (" ", "missing `grant_type` parameter")
])
def test_invalid_request_grant_type(token_handler, context, value, err_descr):
    req = {
        "grant_type": value,
        "code": "abc123",
        "redirect_uri": "https://client.example.com/callback",
        "code_verifier": "s256_code_verifier_sample",
        "refresh_token": "refresh_token_value",
        "scope": "openid profile email"
    }
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    context.request = req
    _assert_invalid_request(
        token_handler.endpoint(context),
        err_descr
    )

@pytest.mark.parametrize("value", ["", None, " "])
def test_invalid_request_code_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code, value):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_authorization_code["code"] = value
    context.request = valid_request_authorization_code

    _assert_invalid_request(
        token_handler.endpoint(context),
        "missing `code` parameter"
    )

def test_invalid_request_code_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_refresh_token["code"] = "value"
    context.request = valid_request_refresh_token

    _assert_invalid_request(
        token_handler.endpoint(context),
        "unexpected `code` parameter"
    )


@pytest.mark.parametrize("value,err_descr", [
    ("" , "missing `redirect_uri` parameter"),
    (None , "missing `redirect_uri` parameter"),
    ("test", "Invalid `redirect_uri`"),
    ("test ", "Invalid `redirect_uri`"),
])
def test_invalid_request_redirect_uri_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code, value, err_descr):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_authorization_code["redirect_uri"] = value
    context.request = valid_request_authorization_code

    _assert_invalid_request(
        token_handler.endpoint(context),
        err_descr
    )

def test_invalid_request_redirect_uri_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_refresh_token["redirect_uri"] = "value"
    context.request = valid_request_refresh_token

    _assert_invalid_request(
        token_handler.endpoint(context),
        "unexpected `redirect_uri` parameter"
    )

@pytest.mark.parametrize("value,err_descr", [
    ("" , "missing `code_verifier` parameter"),
    (None , "missing `code_verifier` parameter"),
    ("test", "Invalid `code_verifier`"),
    ("test ", "Invalid `code_verifier`"),
])
def test_invalid_request_code_verifier_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code, value, err_descr):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_authorization_code["code_verifier"] = value
    context.request = valid_request_authorization_code

    _assert_invalid_request(
        token_handler.endpoint(context),
        err_descr
    )

def test_invalid_request_code_verifier_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_refresh_token["code_verifier"] = "value"
    context.request = valid_request_refresh_token

    _assert_invalid_request(
        token_handler.endpoint(context),
        "unexpected `code_verifier` parameter"
    )

def test_invalid_refresh_token_with_grant_type_c(token_handler, context, valid_request_authorization_code):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_authorization_code["refresh_token"] = "value"
    context.request = valid_request_authorization_code

    _assert_invalid_request(
        token_handler.endpoint(context),
        "unexpected `refresh_token` parameter"
    )

@pytest.mark.parametrize("value", ["", None, " "])
def test_invalid_request_refresh_token_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token, value):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_refresh_token["refresh_token"] = value
    context.request = valid_request_refresh_token

    _assert_invalid_request(
        token_handler.endpoint(context),
        "missing `refresh_token` parameter"
    )

def test_invalid_scopes_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_authorization_code["scope"] = "value"
    context.request = valid_request_authorization_code

    _assert_invalid_request(
        token_handler.endpoint(context),
        "unexpected `scope` parameter"
    )


@pytest.mark.parametrize("value,err_descr", [
    ("test", "invalid scope value 'test'"),
    ("test ","invalid scope value 'test'"),
    ("test scope2", "invalid scope value 'test'"),
])
def test_invalid_request_scope_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token, value, err_descr):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.verify.return_value = None
    token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

    valid_request_refresh_token["scope"] = value
    context.request = valid_request_refresh_token

    _assert_invalid_request(
        token_handler.endpoint(context),
        err_descr
    )

def test_valid_request_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.sign.side_effect = mock_sign
    entity = get_mocked_openid4vpi_entity()
    token_handler.db_engine.get_by_session_id.return_value = entity

    context.request = valid_request_authorization_code

    _assert_valid_request(
        token_handler.endpoint(context),
        entity,
        "fake.access.token",
        "fake.refresh.token"
    )

def test_valid_request_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token):
    token_handler.jws_helper = MagicMock()
    token_handler.jws_helper.sign.side_effect = mock_sign
    entity = get_mocked_openid4vpi_entity()
    token_handler.db_engine.get_by_session_id.return_value = entity

    context.request = valid_request_refresh_token

    _assert_valid_request(
        token_handler.endpoint(context),
        entity,
        "fake.access.token",
        "fake.refresh.token"
    )

def _assert_valid_request(result: Response, entity: OpenId4VCIEntity, exp_access_token:str, exp_refresh_token: str):
    assert result.status == '201 Created'
    response = json.loads(result.message)
    assert response["access_token"] == exp_access_token
    assert response["refresh_token"] ==  exp_refresh_token
    assert response["token_type"] == "DPOP"
    assert isinstance(response["expires_in"], int)
    assert response["authorization_details"] == entity.authorization_details

def _assert_invalid_request(result: Response, error_desc: str):
    assert result.status == '400'
    assert result.message == f'{{"error": "invalid_request", "error_description": "{error_desc}"}}'
