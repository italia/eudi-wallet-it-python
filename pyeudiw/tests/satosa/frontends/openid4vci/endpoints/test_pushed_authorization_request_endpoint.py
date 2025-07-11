import datetime
import json
from copy import deepcopy
from unittest.mock import patch, MagicMock

import pytest
from satosa.context import Context

from pyeudiw.satosa.frontends.openid4vci.endpoints.pushed_authorization_request_endpoint import ParHandler
from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import REQUEST_URI_PREFIX
from pyeudiw.satosa.frontends.openid4vci.models.auhtorization_detail import OPEN_ID_CREDENTIAL_TYPE
from pyeudiw.tests.satosa.frontends.openid4vci.endpoints.endpoints_test import (
    do_test_missing_configurations_raises,
    do_test_invalid_request_method,
    do_test_invalid_content_type,
    do_test_invalid_oauth_client_attestation,
    assert_invalid_request_application_json
)
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    BASE_PACKAGE,
    JWS_HELPER_VERIFY_MODULE,
    INVALID_METHOD_FOR_POST_REQ,
    INVALID_CONTENT_TYPES_NOT_FORM_URLENCODED,
    INVALID_ATTESTATION_HEADERS,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_JWT_CONFIG,
    MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG,
    MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_BASE_URL,
    MOCK_NAME,
    REMOVE,
    mock_deserialized_overridable,
    mock_valid_oauth_client_attestation_jwt,
    get_mocked_satosa_context
)
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, FORM_URLENCODED

_MOCK_VALID_OAUTH_CLIENT_ATTESTATION_JWT = mock_valid_oauth_client_attestation_jwt()
_MOCK_VALID_THUMBPRINT = "b'i5blIsZsKuQAl93ygTPpa_PrZCQZ47Bw9MGPIK-RNnM'"
_MOCK_PAR_REQUEST = {
    "request": "request.valid.jwt",
    "client_id": _MOCK_VALID_THUMBPRINT
}

_PAR_BASE_PATH = f"{BASE_PACKAGE}.endpoints.pushed_authorization_request_endpoint"
_PAR_VALIDATE_OAUTH_CLIENT_ATTESTATION_TARGET = f"{_PAR_BASE_PATH}.validate_oauth_client_attestation"

_MOCK_REQUEST_DESERIALIZED = {
    "iss": _MOCK_VALID_THUMBPRINT,
    "aud": "example.com/openid4vcimock",
    "exp": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 39,
    "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 30,
    "response_type": "code",
    "response_mode": "query",
    "client_id": _MOCK_VALID_THUMBPRINT,
    "state": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "code_challenge": "Xz1T-ZG_i_zMEZtEXAMPLE5pYssH",
    "code_challenge_method": "S256",
    "scope": "openid",
    "authorization_details": [{
        "type": OPEN_ID_CREDENTIAL_TYPE,
        "credential_configuration_id": "dc_sd_jwt_EuropeanDisabilityCard"
    }],
    "redirect_uri": "https://wallet.example.org/callback",
    "jti": f"{_MOCK_VALID_THUMBPRINT}:9a3be9c2-0d2c-4670-a413-fd6b86a59a32",
    "issuer_state": "b5d6b6c1-98ec-4af2-a2b4-23484d9f1e1d"
}

@pytest.fixture
def par_handler() -> ParHandler:
    return ParHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(oauth_client_attestation_header = _MOCK_VALID_OAUTH_CLIENT_ATTESTATION_JWT)

def _mock_configurations(overrides=None):
    return mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, overrides)
def _mock_configuration_removed_oauth_authorization_server_param(field: str):
    metadata_config = { "openid_credential_issuer": MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG}
    if field != "oauth_authorization_server":
        with_removed_field = { k: v for k, v in deepcopy(MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG).items() if k != field }
        metadata_config["oauth_authorization_server"] = with_removed_field
    return _mock_configurations({"metadata": metadata_config})

_removed_par_exp = {k: v for k, v in deepcopy(MOCK_JWT_CONFIG).items() if k != "par_exp"}
_removed_credential_configurations_supported ={ k: v for k, v in deepcopy(MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG).items() if k != "credential_configurations_supported" }
@pytest.mark.parametrize("config, missing_fields", [
    (_mock_configurations({"jwt": _removed_par_exp}), ["jwt.par_exp"]),
    (_mock_configurations({"metadata": {"openid_credential_issuer": MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG}}), ["metadata.oauth_authorization_server"]),
    (_mock_configurations({"metadata": {"oauth_authorization_server": MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG, "openid_credential_issuer": _removed_credential_configurations_supported}}), ["metadata.openid_credential_issuer.credential_configurations_supported"]),
    (_mock_configuration_removed_oauth_authorization_server_param("response_types_supported"), ["metadata.oauth_authorization_server.response_types_supported"]),
    (_mock_configuration_removed_oauth_authorization_server_param("response_modes_supported"), ["metadata.oauth_authorization_server.response_modes_supported"]),
    (_mock_configuration_removed_oauth_authorization_server_param("code_challenge_methods_supported"), ["metadata.oauth_authorization_server.code_challenge_methods_supported"]),
    (_mock_configuration_removed_oauth_authorization_server_param("oauth_authorization_server"), ["metadata.oauth_authorization_server"]),
    (_mock_configurations({"jwt": _removed_par_exp, "metadata": {"oauth_authorization_server": MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG, "openid_credential_issuer": _removed_credential_configurations_supported}}), ["jwt.par_exp", "metadata.openid_credential_issuer.credential_configurations_supported"])
])
def test_missing_configurations(config, missing_fields):
    do_test_missing_configurations_raises(ParHandler, config, missing_fields)

@pytest.mark.parametrize("method", INVALID_METHOD_FOR_POST_REQ)
def test_invalid_request_method(par_handler, context, method):
    do_test_invalid_request_method(par_handler, context, method)

@pytest.mark.parametrize("content_type", INVALID_CONTENT_TYPES_NOT_FORM_URLENCODED)
def test_invalid_content_type(par_handler, context, content_type):
    do_test_invalid_content_type(par_handler, context, content_type)

@pytest.mark.parametrize("headers", INVALID_ATTESTATION_HEADERS)
def test_invalid_oauth_client_attestation(par_handler, headers):
    headers[HTTP_CONTENT_TYPE_HEADER] = FORM_URLENCODED
    do_test_invalid_oauth_client_attestation(par_handler, headers)

@pytest.mark.parametrize("client_id, request_par", [
    (None, None),
    (None, ""),
    ("", None),
    (" ", " "),
])
def test_invalid_request(par_handler, context,
                         client_id, request_par):
    req = None
    if client_id:
        req = req or {}
        req["client_id"] = client_id
    if request_par:
        req = req or {}
        req["request"] = request_par

    context.request = req
    assert_invalid_request_application_json(
        par_handler.endpoint(context),
        "invalid request parameters"
    )


def _mock_request_deserialized(overrides=None):
    return mock_deserialized_overridable(_MOCK_REQUEST_DESERIALIZED, overrides)

@pytest.mark.parametrize("decoded_request, error_desc", [
    # invalid iss
    (_mock_request_deserialized({"iss": ""}), "missing `iss` parameter"),
    (_mock_request_deserialized({"iss": None}), "invalid `iss` parameter"),
    (_mock_request_deserialized({"iss": " "}), "missing `iss` parameter"),
    (_mock_request_deserialized({"iss": REMOVE}), "missing `iss` parameter"),
    (_mock_request_deserialized({"iss": "invalid_client_id"}), "invalid `iss` parameter"),
    # invalid aud
    (_mock_request_deserialized({"aud": ""}), "missing `aud` parameter"),
    (_mock_request_deserialized({"aud": None}), "invalid `aud` parameter"),
    (_mock_request_deserialized({"aud": " "}), "missing `aud` parameter"),
    (_mock_request_deserialized({"aud": REMOVE}), "missing `aud` parameter"),
    (_mock_request_deserialized({"aud": "invalid_aud"}), "invalid `aud` parameter"),
    # invalid state
    (_mock_request_deserialized({"state": ""}), "missing `state` parameter"),
    (_mock_request_deserialized({"state": None}), "invalid `state` parameter"),
    (_mock_request_deserialized({"state": " "}), "missing `state` parameter"),
    (_mock_request_deserialized({"state": REMOVE}), "missing `state` parameter"),
    (_mock_request_deserialized({"state": "invalid_state"}), "invalid `state` parameter"),
    # invalid client_id
    (_mock_request_deserialized({"client_id": ""}), "missing `client_id` parameter"),
    (_mock_request_deserialized({"client_id": None}), "invalid `client_id` parameter"),
    (_mock_request_deserialized({"client_id": " "}), "missing `client_id` parameter"),
    (_mock_request_deserialized({"client_id": REMOVE}), "missing `client_id` parameter"),
    (_mock_request_deserialized({"client_id": "invalid_client_id"}), "invalid `client_id` parameter"),
    # invalid exp
    (_mock_request_deserialized({"exp": ""}), "invalid `exp` parameter"),
    (_mock_request_deserialized({"exp": None}), "invalid `exp` parameter"),
    (_mock_request_deserialized({"exp": " "}), "invalid `exp` parameter"),
    (_mock_request_deserialized({"exp": REMOVE}), "invalid `exp` parameter"),
    (_mock_request_deserialized({"exp": 0}), "invalid `exp` parameter"),
    # invalid iat
    (_mock_request_deserialized({"iat": ""}), "invalid `iat` parameter"),
    (_mock_request_deserialized({"iat": None}), "invalid `iat` parameter"),
    (_mock_request_deserialized({"iat": " "}), "invalid `iat` parameter"),
    (_mock_request_deserialized({"iat": REMOVE}), "invalid `iat` parameter"),
    (_mock_request_deserialized({"iat": 0}), "invalid `iat` parameter"),
    (_mock_request_deserialized({"iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 10000}), "invalid `iat` parameter"),
    # expired token
    (_mock_request_deserialized({"iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()), "exp": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 329}), "expired token"),
    # invalid response_type
    (_mock_request_deserialized({"response_type": ""}), "missing `response_type` parameter"),
    (_mock_request_deserialized({"response_type": None}), "invalid `response_type` parameter"),
    (_mock_request_deserialized({"response_type": " "}), "missing `response_type` parameter"),
    (_mock_request_deserialized({"response_type": REMOVE}), "missing `response_type` parameter"),
    (_mock_request_deserialized({"response_type": "response_type"}), "invalid `response_type` parameter"),
    # invalid response_mode
    (_mock_request_deserialized({"response_mode": ""}), "missing `response_mode` parameter"),
    (_mock_request_deserialized({"response_mode": None}), "invalid `response_mode` parameter"),
    (_mock_request_deserialized({"response_mode": " "}), "missing `response_mode` parameter"),
    (_mock_request_deserialized({"response_mode": REMOVE}), "missing `response_mode` parameter"),
    (_mock_request_deserialized({"response_mode": "response_mode"}), "invalid `response_mode` parameter"),
    # invalid code_challenge
    (_mock_request_deserialized({"code_challenge": ""}), "missing `code_challenge` parameter"),
    (_mock_request_deserialized({"code_challenge": None}), "invalid `code_challenge` parameter"),
    (_mock_request_deserialized({"code_challenge": " "}), "missing `code_challenge` parameter"),
    (_mock_request_deserialized({"code_challenge": REMOVE}), "missing `code_challenge` parameter"),
    # invalid code_challenge_method
    (_mock_request_deserialized({"code_challenge_method": ""}), "missing `code_challenge_method` parameter"),
    (_mock_request_deserialized({"code_challenge_method": None}), "invalid `code_challenge_method` parameter"),
    (_mock_request_deserialized({"code_challenge_method": " "}), "missing `code_challenge_method` parameter"),
    (_mock_request_deserialized({"code_challenge_method": REMOVE}), "missing `code_challenge_method` parameter"),
    (_mock_request_deserialized({"code_challenge_method": "code_challenge_method"}), "invalid `code_challenge_method` parameter"),
    # invalid redirect_uri
    (_mock_request_deserialized({"redirect_uri": ""}), "missing `redirect_uri` parameter"),
    (_mock_request_deserialized({"redirect_uri": None}), "invalid `redirect_uri` parameter"),
    (_mock_request_deserialized({"redirect_uri": " "}), "missing `redirect_uri` parameter"),
    (_mock_request_deserialized({"redirect_uri": REMOVE}), "missing `redirect_uri` parameter"),
    (_mock_request_deserialized({"redirect_uri": "https://wallet.example.org"}), "invalid `redirect_uri` parameter"),
    (_mock_request_deserialized({"redirect_uri": "wallet.example.org/callback"}), "invalid `redirect_uri` parameter"),
    (_mock_request_deserialized({"redirect_uri": "https:///callback"}), "invalid `redirect_uri` parameter"),
    (_mock_request_deserialized({"redirect_uri": "invalid_redirect_uri"}), "invalid `redirect_uri` parameter"),
    # invalid jti
    (_mock_request_deserialized({"jti": ""}), "missing `jti` parameter"),
    (_mock_request_deserialized({"jti": None}), "invalid `jti` parameter"),
    (_mock_request_deserialized({"jti": " "}), "missing `jti` parameter"),
    (_mock_request_deserialized({"jti": REMOVE}), "missing `jti` parameter"),
    (_mock_request_deserialized({"jti": "invalid_jti"}), "invalid `jti` parameter"),
    (_mock_request_deserialized({"jti": "urn:example:wallet:12345"}), "invalid `jti` parameter"),
    # invalid authorization_details and scope
    (_mock_request_deserialized({"scope": "","authorization_details": ""}), "invalid `authorization_details` parameter"),
    (_mock_request_deserialized({"scope": None,"authorization_details": None}), "Missing `scope` and `authorization_details` in `par` endpoint"),
    (_mock_request_deserialized({"scope": " ","authorization_details": " "}), "invalid `authorization_details` parameter"),
    (_mock_request_deserialized({"scope": REMOVE,"authorization_details": REMOVE}), "Missing `scope` and `authorization_details` in `par` endpoint"),
    (_mock_request_deserialized({"scope": None,"authorization_details": []}), "Missing `scope` and `authorization_details` in `par` endpoint"),
    (_mock_request_deserialized({"authorization_details": [{"type": OPEN_ID_CREDENTIAL_TYPE}]}), "missing `authorization_details.credential_configuration_id` parameter"),
    (_mock_request_deserialized({"authorization_details": [{"credential_configuration_id": "dc_sd_jwt_EuropeanDisabilityCard"}]}), "missing `authorization_details.type` parameter"),
    (_mock_request_deserialized({"authorization_details": [{"type": OPEN_ID_CREDENTIAL_TYPE, "credential_configuration_id": "invalid_credential_configuration_id"}]}), "invalid `authorization_details.credential_configuration_id` parameter"),
    (_mock_request_deserialized({"authorization_details": [{"type": "invalid_credential_type", "credential_configuration_id": "dc_sd_jwt_EuropeanDisabilityCard"}]}), "invalid `authorization_details.type` parameter")
])
def test_invalid_request_deserialized(par_handler, context,
                                      decoded_request, error_desc):
    with (patch(JWS_HELPER_VERIFY_MODULE, return_value = decoded_request),
          patch(_PAR_VALIDATE_OAUTH_CLIENT_ATTESTATION_TARGET, return_value = {
              "thumbprint": _MOCK_VALID_THUMBPRINT
          })):
        context.request = _MOCK_PAR_REQUEST
        assert_invalid_request_application_json(
            par_handler.endpoint(context),
            error_desc
        )

def test_valid_request(par_handler, context):
    with (patch(JWS_HELPER_VERIFY_MODULE, return_value = _mock_request_deserialized()),
          patch(_PAR_VALIDATE_OAUTH_CLIENT_ATTESTATION_TARGET, return_value = {
              "thumbprint": _MOCK_VALID_THUMBPRINT
          })):
        context.request = _MOCK_PAR_REQUEST
        par_handler.db_engine = MagicMock()
        result = par_handler.endpoint(context)

        assert result.status == '201 Created'
        response = json.loads(result.message)
        assert response["request_uri"] is not None
        assert response["request_uri"].startswith(REQUEST_URI_PREFIX)
        assert response["expires_in"] == 90
