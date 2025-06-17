import datetime
import json
from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest
from satosa.context import Context

from pyeudiw.openid4vci.endpoints.credential_endpoint import CredentialHandler
from pyeudiw.openid4vci.models.auhtorization_detail import OPEN_ID_CREDENTIAL_TYPE
from pyeudiw.openid4vci.models.credential_endpoint_request import JWT_PROOF_TYP
from pyeudiw.storage.user_entity import UserEntity
from pyeudiw.tests.openid4vci.endpoints.endpoints_test import (
    do_test_missing_configurations_raises,
    do_test_invalid_request_method,
    do_test_invalid_content_type,
    do_test_invalid_oauth_client_attestation,
    assert_invalid_request_application_json
)
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    INVALID_ATTESTATION_HEADERS,
    INVALID_METHOD_FOR_POST_REQ,
    INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_CREDENTIAL_CONFIGURATIONS,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    mock_deserialized_overridable,
    get_mocked_satosa_context,
    get_mocked_openid4vpi_entity
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON
)

VALID_PROOF = {
    "proof_type": "jwt",
    "jwt": "my_jwt"
}

@pytest.fixture
def valid_request_proof_jwt():
    return {
        "alg": "ES256",
        "typ": JWT_PROOF_TYP,
        "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}',
        "iss": "client123",
        "aud": "example.com/openid4vcimock",
        "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30,
        "nonce": "random-nonce-abc123"
    }

@pytest.fixture
def request_without_open_id_credential():
    return {
        "credential_configuration_id": "example_configuration_id_456",
        "proof": VALID_PROOF
    }

@pytest.fixture
def request_with_open_id_credential():
    return {
        "credential_identifier": "example_credential_id_123",
        "proof": VALID_PROOF
    }


@pytest.fixture
def credential_handler() -> CredentialHandler:
    handler = CredentialHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    handler.db_engine = MagicMock()
    handler._db_user_engine = MagicMock()
    handler.jws_helper = MagicMock()
    return handler

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(content_type = APPLICATION_JSON)

def _mock_configurations(overrides=None):
    return mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, overrides)

_removed_credential_specification_template = {k: v for k, v in deepcopy(MOCK_CREDENTIAL_CONFIGURATIONS).items() if k != "credential_specification_template"}
@pytest.mark.parametrize("config, missing_fields", [
    (_mock_configurations({"credential_configurations": _removed_credential_specification_template}), ["credential_configurations.credential_specification_template"]),
])
def test_missing_configurations_raises(config, missing_fields):
    do_test_missing_configurations_raises(CredentialHandler, config, missing_fields)

@pytest.mark.parametrize("method", INVALID_METHOD_FOR_POST_REQ)
def test_invalid_request_method(credential_handler, context, method):
    do_test_invalid_request_method(credential_handler, context, method)

@pytest.mark.parametrize("content_type", INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON)
def test_invalid_content_type(credential_handler, context, content_type):
    do_test_invalid_content_type(credential_handler, context, content_type)

@pytest.mark.parametrize("headers", INVALID_ATTESTATION_HEADERS)
def test_invalid_oauth_client_attestation(credential_handler, headers):
    headers[HTTP_CONTENT_TYPE_HEADER] = APPLICATION_JSON
    do_test_invalid_oauth_client_attestation(credential_handler, headers)

@pytest.mark.parametrize("credential_configuration_id,credential_identifier,error_desc", [
    ("", "", "missing `credential_configuration_id` parameter"),
    (None, "", "missing `credential_configuration_id` parameter"),
    (" ", "", "missing `credential_configuration_id` parameter"),
    ("credential_configuration_id", "credential_identifier", "unexpected `credential_identifier` parameter"),
])
def test_invalid_request_credential_id_without_openid_credential_in_auth_details(
        credential_handler, context,
        credential_configuration_id,credential_identifier,error_desc):
    credential_handler.db_engine.get_by_session_id.return_value = get_mocked_openid4vpi_entity()
    req = {"proof": VALID_PROOF}
    if credential_configuration_id:
        req["credential_configuration_id"] = credential_configuration_id
    if credential_identifier:
        req["credential_identifier"] = credential_identifier

    context.request = req

    assert_invalid_request_application_json(
        credential_handler.endpoint(context),
        error_desc
    )

@pytest.mark.parametrize("credential_identifier,credential_configuration_id,error_desc", [
    ("", "", "missing `credential_identifier` parameter"),
    (None, "", "missing `credential_identifier` parameter"),
    (" ", "", "missing `credential_identifier` parameter"),
    ("cred1", "cred_config_id", "unexpected `credential_configuration_id` parameter"),
    ("cred21", None, "invalid `credential_identifier` parameter"),
])
def test_invalid_request_credential_id_with_openid_credential_in_auth_details(
        credential_handler, context,
        credential_identifier,credential_configuration_id, error_desc):
    entity = deepcopy(get_mocked_openid4vpi_entity())
    entity.authorization_details = [
        {
            "type": OPEN_ID_CREDENTIAL_TYPE,
            "credential_configuration_id": "credential_configuration_id_test",
            "credential_identifiers": ["cred1", "cred2"]
        }
    ]
    credential_handler.db_engine.get_by_session_id.return_value = entity
    req = {"proof": VALID_PROOF}
    if credential_configuration_id:
        req["credential_configuration_id"] = credential_configuration_id
    if credential_identifier:
        req["credential_identifier"] = credential_identifier

    context.request = req

    assert_invalid_request_application_json(
        credential_handler.endpoint(context),
        error_desc
    )

@pytest.mark.parametrize("value,error_desc", [
    ("", "missing `proof.proof_type` parameter"),
    (None, "invalid `proof` parameter"),
    (" ", "missing `proof.proof_type` parameter"),
])
def test_request_invalid_prof_type(credential_handler, context, value, error_desc, request_without_open_id_credential):
    req = deepcopy(request_without_open_id_credential)
    req["proof"]["proof_type"] = value
    context.request = req
    assert_invalid_request_application_json(
        credential_handler.endpoint(context),
        error_desc
    )

@pytest.mark.parametrize("value,error_desc", [
    ("", "missing `proof.jwt` parameter"),
    (None, "invalid `proof` parameter"),
    (" ", "missing `proof.jwt` parameter"),
])
def test_request_invalid_prof_jwt(credential_handler, context, request_without_open_id_credential,
                                   value, error_desc):
    req = deepcopy(request_without_open_id_credential)
    req["proof"]["jwt"] = value
    context.request = req
    assert_invalid_request_application_json(
        credential_handler.endpoint(context),
        error_desc
    )


@pytest.mark.parametrize("value,error_desc", [
    ({"alg": "", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.alg` parameter"),
    ({"alg": None, "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "invalid `alg` parameter"),
    ({"alg": " ", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.alg` parameter"),
    ({"typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.alg` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.iss` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": None, "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "invalid `iss` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": " ", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.iss` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.iss` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "randomiss", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "invalid `proof.jwt.iss` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.aud` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": None, "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "invalid `aud` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": " ", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.aud` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "missing `proof.jwt.aud` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "randomaud", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-nonce-abc123"}, "invalid `proof.jwt.aud` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 30000, "nonce": "random-nonce-abc123"}, "invalid `proof.jwt.iat` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": None, "nonce": "random-nonce-abc123"}, "invalid `iat` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": 0, "nonce": "random-nonce-abc123"}, "invalid `proof.jwt.iat` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "nonce": "random-nonce-abc123"}, "invalid `proof.jwt.iat` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": ""}, "missing `proof.jwt.nonce` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": None}, "invalid `nonce` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": " "}, "missing `proof.jwt.nonce` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30}, "missing `proof.jwt.nonce` parameter"),
    ({"alg": "ES256", "typ": JWT_PROOF_TYP, "jwk": '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}', "iss": "client123", "aud": "example.com/openid4vcimock", "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30, "nonce": "random-random-nonce-abc123"}, "invalid `proof.jwt.nonce` parameter")
])
def test_request_invalid_prof_jwt_decoded(credential_handler, context, request_without_open_id_credential,
                                          value, error_desc):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = value):
        context.request = request_without_open_id_credential
        entity = deepcopy(get_mocked_openid4vpi_entity())
        entity.c_nonce = "random-nonce-abc123"
        credential_handler.db_engine.get_by_session_id.return_value = entity
        result = credential_handler.endpoint(context)
        assert_invalid_request_application_json(
            result,
            error_desc
        )

def side_effect(fields):
    if fields == {'fiscal_code': 'RSSMRA80A01H501T'}:
        return UserEntity(**{
            "name": "Mario",
            "surname": "Rossi",
            "fiscal_code":"RSSMRA80A01H501T",
            "dateOfBirth":"1980-01-01",
            "placeOfBirth": "Roma",
            "countyOfBirth": "IT",
            "mail": "mario.rossi@example.com"
        })
    pytest.fail(f"Unexpected lookup fields: {fields}")

def test_request_without_open_id_credential(credential_handler, context, request_without_open_id_credential, valid_request_proof_jwt):
    context.request = request_without_open_id_credential
    entity = deepcopy(get_mocked_openid4vpi_entity())
    _do_test_request_valid(credential_handler, context, valid_request_proof_jwt, entity)


def test_request_with_open_id_credential(credential_handler, context, request_with_open_id_credential, valid_request_proof_jwt):
    context.request = request_with_open_id_credential
    entity = deepcopy(get_mocked_openid4vpi_entity())
    entity.authorization_details = [
        {
            "type": OPEN_ID_CREDENTIAL_TYPE,
            "credential_configuration_id": "credential_configuration_id_test",
            "credential_identifiers": ["cred1", "cred2", "example_credential_id_123"]
        }
    ]
    _do_test_request_valid(credential_handler, context, valid_request_proof_jwt, entity)

def _do_test_request_valid(credential_handler, context, valid_request_proof_jwt, entity):
    with patch("pyeudiw.jwt.jws_helper.JWSHelper.verify", return_value = valid_request_proof_jwt):
        entity.c_nonce = "random-nonce-abc123"
        entity.attributes = {
            "name": ["Mario"],
            "surname": ["Rossi"],
            "fiscal_number": ["RSSMRA80A01H501T"],
            "birthdate": ["1980-01-01"],
            "place_of_birth": ["Roma"],
            "gender": ["M"]
        }
        db_user_mock = MagicMock()
        db_user_mock.get_by_fields.side_effect = side_effect

        credential_handler._db_user_engine = db_user_mock
        credential_handler.db_engine.get_by_session_id.return_value = entity
        result = credential_handler.endpoint(context)

        assert result.status == '200 OK'
        response = json.loads(result.message)
        assert response["credentials"] is not None
        assert isinstance(response["credentials"], list)
        assert len(response["credentials"]) == 1
