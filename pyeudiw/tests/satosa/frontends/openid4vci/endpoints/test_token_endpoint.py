import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest
from satosa.context import Context
from satosa.response import Response

from pyeudiw.satosa.frontends.openid4vci.endpoints.token_endpoint import TokenHandler, TokenTypsEnum
from pyeudiw.satosa.frontends.openid4vci.models.token_request import (
    AUTHORIZATION_CODE_GRANT,
    REFRESH_TOKEN_GRANT
)
from pyeudiw.satosa.frontends.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.satosa.utils.validation import (
    OAUTH_CLIENT_ATTESTATION_POP_HEADER
)
from pyeudiw.tests.satosa.frontends.openid4vci.endpoints.endpoints_test import (
    do_test_invalid_content_type,
    do_test_invalid_request_method, do_test_invalid_oauth_client_attestation, do_test_missing_configurations_raises
)
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    INVALID_ATTESTATION_HEADERS,
    INVALID_METHOD_FOR_POST_REQ,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_ENDPOINTS_CONFIG,
    MOCK_JWT_CONFIG,
    MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG,
    MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG,
    MOCK_USER_STORAGE_CONFIG,
    MOCK_CREDENTIAL_STORAGE_CONFIG,
    MOCK_METADATA_JWKS_CONFIG,
    MOCK_CREDENTIAL_CONFIGURATIONS,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context,
    get_mocked_openid4vpi_entity
)


def mock_sign(*args, **kwargs):
    typ = kwargs.get("protected", {}).get("typ")
    if typ == TokenTypsEnum.ACCESS_TOKEN_TYP.value:
        return "fake.access.token"
    elif typ == TokenTypsEnum.REFRESH_TOKEN_TYP.value:
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
    do_test_invalid_request_method(token_handler, context, method)

def _mock_configurations(field: str):
    config = {
        "endpoints": MOCK_ENDPOINTS_CONFIG,
        "jwt": MOCK_JWT_CONFIG,
        "metadata": {
            "openid_credential_issuer": MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG,
            "oauth_authorization_server": MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG
        },
        "credential_storage": MOCK_CREDENTIAL_STORAGE_CONFIG,
        "user_storage": MOCK_USER_STORAGE_CONFIG,
        "metadata_jwks": MOCK_METADATA_JWKS_CONFIG,
        "credential_configurations": MOCK_CREDENTIAL_CONFIGURATIONS,
    }
    match field:
        case "access_token_exp":
            jwt = deepcopy(MOCK_JWT_CONFIG)
            jwt.pop("access_token_exp", None)
            config["jwt"] = jwt
        case "refresh_token_exp":
            jwt = deepcopy(MOCK_JWT_CONFIG)
            jwt.pop("refresh_token_exp", None)
            config["jwt"] = jwt
        case "access_token_exp,refresh_token_exp":
            jwt = deepcopy(MOCK_JWT_CONFIG)
            jwt.pop("access_token_exp", None)
            jwt.pop("refresh_token_exp", None)
            config["jwt"] = jwt
        case "oauth_authorization_server":
            config["metadata"] = {
                "openid_credential_issuer": MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG,
            }
        case "oauth_authorization_server.scopes_supported":
            oauth_authorization_server = deepcopy(MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG)
            oauth_authorization_server.pop("scopes_supported", None)
            config["metadata"]["oauth_authorization_server"] = oauth_authorization_server
        case "oauth_authorization_server.scopes_supported[]":
            oauth_authorization_server = deepcopy(MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG)
            oauth_authorization_server["scopes_supported"] = []
            config["metadata"]["oauth_authorization_server"] = oauth_authorization_server
        case _:
            config = config
    return config

@pytest.mark.parametrize("config, missing_fields", [
    (_mock_configurations("access_token_exp"), ["jwt.access_token_exp"]),
    (_mock_configurations("refresh_token_exp"), ["jwt.refresh_token_exp"]),
    (_mock_configurations("oauth_authorization_server"), ["metadata.oauth_authorization_server"]),
    (_mock_configurations("oauth_authorization_server.scopes_supported"), ["metadata.oauth_authorization_server.scopes_supported"]),
    (_mock_configurations("oauth_authorization_server.scopes_supported[]"), ["metadata.oauth_authorization_server.scopes_supported"]),
    (_mock_configurations("access_token_exp,refresh_token_exp"), ["jwt.access_token_exp", "jwt.refresh_token_exp"])
])
def test_missing_configurations(config, missing_fields):
    do_test_missing_configurations_raises(TokenHandler, config, missing_fields)


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
    do_test_invalid_content_type(token_handler, context, content_type)

@pytest.mark.parametrize("headers", INVALID_ATTESTATION_HEADERS)
def test_invalid_oauth_client_attestation(token_handler, headers):
    do_test_invalid_oauth_client_attestation(token_handler, headers)

@pytest.mark.parametrize("pop", [
    "valid-pop",
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJub3QtcmVhbCIsImV4cCI6MTY4MDAwMDAwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
])
def test_invalid_jwt_oauth_client_attestation_pop(token_handler, context, pop):
    ctx = deepcopy(context)
    ctx.http_headers[OAUTH_CLIENT_ATTESTATION_POP_HEADER] = pop
    _assert_invalid_request(
        token_handler.endpoint(ctx),
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
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        context.request = {
            "grant_type": value,
            "code": "abc123",
            "redirect_uri": "https://client.example.com/callback",
            "code_verifier": "s256_code_verifier_sample",
            "refresh_token": "refresh_token_value",
            "scope": "openid profile email"
        }
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
        _assert_invalid_request(
            token_handler.endpoint(context),
            err_descr
        )

@pytest.mark.parametrize("value", ["", None, " "])
def test_invalid_request_code_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code, value):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

        valid_request_authorization_code["code"] = value
        context.request = valid_request_authorization_code

        _assert_invalid_request(
            token_handler.endpoint(context),
            "missing `code` parameter"
        )

def test_invalid_request_code_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
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
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

        valid_request_authorization_code["redirect_uri"] = value
        context.request = valid_request_authorization_code

        _assert_invalid_request(
            token_handler.endpoint(context),
            err_descr
        )

def test_invalid_request_redirect_uri_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
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
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

        valid_request_authorization_code["code_verifier"] = value
        context.request = valid_request_authorization_code

        _assert_invalid_request(
            token_handler.endpoint(context),
            err_descr
        )

def test_invalid_request_code_verifier_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

        valid_request_refresh_token["code_verifier"] = "value"
        context.request = valid_request_refresh_token

        _assert_invalid_request(
            token_handler.endpoint(context),
            "unexpected `code_verifier` parameter"
        )

def test_invalid_refresh_token_with_grant_type_c(token_handler, context, valid_request_authorization_code):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

        valid_request_authorization_code["refresh_token"] = "value"
        context.request = valid_request_authorization_code

        _assert_invalid_request(
            token_handler.endpoint(context),
            "unexpected `refresh_token` parameter"
        )

@pytest.mark.parametrize("value", ["", None, " "])
def test_invalid_request_refresh_token_with_grant_type_refresh_token(token_handler, context, valid_request_refresh_token, value):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

        valid_request_refresh_token["refresh_token"] = value
        context.request = valid_request_refresh_token

        _assert_invalid_request(
            token_handler.endpoint(context),
            "missing `refresh_token` parameter"
        )

def test_invalid_scopes_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
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
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None):
        token_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()

        valid_request_refresh_token["scope"] = value
        context.request = valid_request_refresh_token

        _assert_invalid_request(
            token_handler.endpoint(context),
            err_descr
        )

def test_valid_request_with_grant_type_authorization_code(token_handler, context, valid_request_authorization_code):
    with (patch("pyeudiw.jwt.jws_helper.JWSHelper.sign", side_effect = mock_sign),
          patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None)):
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
    with (patch("pyeudiw.jwt.jws_helper.JWSHelper.sign", side_effect = mock_sign),
          patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = None)):
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
    assert response["authorization_details"] == None \
        if not entity.authorization_details and len(entity.authorization_details) == 0 \
        else entity.authorization_details

def _assert_invalid_request(result: Response, error_desc: str):
    assert result.status == '400'
    assert result.message == f'{{"error": "invalid_request", "error_description": "{error_desc}"}}'
