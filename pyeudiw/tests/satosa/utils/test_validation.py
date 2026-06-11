import json

import pytest
from cryptojwt import JWS
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.jwk import key_from_jwk_dict

from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.utils.validation import (
    OAUTH_CLIENT_ATTESTATION_HEADER,
    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
    validate_content_type,
    validate_oauth_client_attestation,
    validate_oauth_client_attestation_pop,
    validate_request_method,
)
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    get_mocked_satosa_context,
)
from pyeudiw.tools.content_type import (
    APPLICATION_JSON,
    FORM_URLENCODED,
    HTTP_CONTENT_TYPE_HEADER,
)

_TRUST_CHAIN_TARGET = "pyeudiw.satosa.utils.validation.validate_subject_trust_chain"
_WALLET_PROVIDER_ISS = "https://wallet-provider.example.org"
_AUTHORITY_HINTS = ["https://trust-anchor.example.org"]
_HTTPC_PARAMS = {"connection": {"ssl": True}, "session": {"timeout": 4}}


def _thumbprint(jwk_dict: dict) -> str:
    return key_from_jwk_dict(jwk_dict).thumbprint("SHA-256").decode()


def _context(method: str = "POST", content_type: str = APPLICATION_JSON, **headers):
    """Build a SATOSA Context carrying the given request method, content-type and headers.

    Mirrors how the OpenID4VCI endpoints invoke these validators: request data is
    always sourced from ``context.request_method`` / ``context.http_headers``.
    """
    http_headers = {HTTP_CONTENT_TYPE_HEADER: content_type}
    http_headers.update(headers)
    return get_mocked_satosa_context(method=method, headers=http_headers)


@pytest.fixture
def wallet_provider_key():
    return new_ec_key(crv="P-256", use="sig", kid="wp-key", alg="ES256")


@pytest.fixture
def wallet_instance_key():
    return new_ec_key(crv="P-256", use="sig", kid="wia-key", alg="ES256")


@pytest.fixture
def cnf_jwk(wallet_instance_key):
    return wallet_instance_key.serialize(private=False)


@pytest.fixture
def valid_oauth_client_attestation_jwt(wallet_provider_key, cnf_jwk):
    payload = {
        "iss": _WALLET_PROVIDER_ISS,
        "sub": _thumbprint(cnf_jwk),
        "exp": 9999999999,
        "cnf": {"jwk": cnf_jwk},
    }
    header = {
        "alg": "ES256",
        "typ": "oauth-client-attestation+jwt",
        "kid": wallet_provider_key.kid,
        "x5c": ["MIID-dummy-certificate"],
    }
    return JWS(json.dumps(payload), alg="ES256").sign_compact(
        [wallet_provider_key], protected=header
    )


@pytest.fixture
def valid_oauth_client_attestation_pop_jwt(wallet_instance_key, cnf_jwk):
    payload = {
        "iss": _thumbprint(cnf_jwk),
        "aud": _WALLET_PROVIDER_ISS,
        "exp": 9999999999,
    }
    return JWS(json.dumps(payload), alg="ES256").sign_compact(
        [wallet_instance_key], protected={"alg": "ES256", "typ": "JWT"}
    )


@pytest.fixture
def trust_chain_result(wallet_provider_key):
    return {
        "metadata": {
            "wallet_solution": {
                "jwks": {"keys": [wallet_provider_key.serialize(private=False)]}
            }
        }
    }


def test_validate_content_type_form_urlencoded_valid():
    context = _context(content_type=FORM_URLENCODED)
    validate_content_type(
        context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED
    )


def test_validate_content_type_form_urlencoded_invalid():
    context = _context(content_type="text/plain")
    with pytest.raises(InvalidRequestException):
        validate_content_type(
            context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED
        )


def test_validate_content_type_application_json_valid():
    context = _context(content_type=APPLICATION_JSON)
    validate_content_type(
        context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON
    )


def test_validate_content_type_application_json_invalid():
    context = _context(content_type="application/xml")
    with pytest.raises(InvalidRequestException):
        validate_content_type(
            context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON
        )


@pytest.mark.parametrize("method", ["POST", "GET"])
def test_validate_request_method_valid(method):
    context = _context(method=method)
    validate_request_method(context.request_method, ["GET", "POST"])


@pytest.mark.parametrize("method", [None, "DELETE", ""])
def test_validate_request_method_invalid(method):
    context = _context(method=method)
    with pytest.raises(InvalidRequestException):
        validate_request_method(context.request_method, ["GET", "POST"])


def test_validate_oauth_client_attestation_valid_without_signing_alg_values_supported(
    valid_oauth_client_attestation_jwt, trust_chain_result, cnf_jwk
):
    context = _context(
        **{OAUTH_CLIENT_ATTESTATION_HEADER: valid_oauth_client_attestation_jwt}
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_TRUST_CHAIN_TARGET, lambda *args, **kwargs: trust_chain_result)
        result = validate_oauth_client_attestation(
            context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER),
            _AUTHORITY_HINTS,
            _HTTPC_PARAMS,
            None,
        )
    assert isinstance(result, dict)
    assert result["iss"] == _WALLET_PROVIDER_ISS
    assert result["sub"] == _thumbprint(cnf_jwk)


def test_validate_oauth_client_attestation_valid(
    valid_oauth_client_attestation_jwt, trust_chain_result, cnf_jwk
):
    context = _context(
        **{OAUTH_CLIENT_ATTESTATION_HEADER: valid_oauth_client_attestation_jwt}
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_TRUST_CHAIN_TARGET, lambda *args, **kwargs: trust_chain_result)
        result = validate_oauth_client_attestation(
            context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER),
            _AUTHORITY_HINTS,
            _HTTPC_PARAMS,
            ["ES256", "ES384", "ES512"],
        )
    assert isinstance(result, dict)
    assert result["sub"] == _thumbprint(cnf_jwk)


def test_validate_oauth_client_attestation_unsupported_signing_alg(
    valid_oauth_client_attestation_jwt, trust_chain_result
):
    context = _context(
        **{OAUTH_CLIENT_ATTESTATION_HEADER: valid_oauth_client_attestation_jwt}
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_TRUST_CHAIN_TARGET, lambda *args, **kwargs: trust_chain_result)
        with pytest.raises(InvalidRequestException):
            validate_oauth_client_attestation(
                context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER),
                _AUTHORITY_HINTS,
                _HTTPC_PARAMS,
                ["ES384", "ES512"],
            )


def test_validate_oauth_client_attestation_invalid_trust_chain(
    valid_oauth_client_attestation_jwt
):
    context = _context(
        **{OAUTH_CLIENT_ATTESTATION_HEADER: valid_oauth_client_attestation_jwt}
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_TRUST_CHAIN_TARGET, lambda *args, **kwargs: None)
        with pytest.raises(InvalidRequestException):
            validate_oauth_client_attestation(
                context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER),
                _AUTHORITY_HINTS,
                _HTTPC_PARAMS,
                None,
            )


@pytest.mark.parametrize("client_attestation", ["", None])
def test_validate_oauth_client_attestation_missing(client_attestation):
    context = _context(**{OAUTH_CLIENT_ATTESTATION_HEADER: client_attestation})
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation(
            context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER),
            _AUTHORITY_HINTS,
            _HTTPC_PARAMS,
            None,
        )


def test_validate_oauth_client_attestation_invalid_structure():
    context = _context(**{OAUTH_CLIENT_ATTESTATION_HEADER: "not-a-jwt"})
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation(
            context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER),
            _AUTHORITY_HINTS,
            _HTTPC_PARAMS,
            None,
        )


def test_validate_oauth_client_attestation_pop_valid(
    valid_oauth_client_attestation_pop_jwt, cnf_jwk
):
    context = _context(
        **{OAUTH_CLIENT_ATTESTATION_POP_HEADER: valid_oauth_client_attestation_pop_jwt}
    )
    result = validate_oauth_client_attestation_pop(
        context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER),
        cnf_jwk,
        ["ES256"],
    )
    assert isinstance(result, dict)
    assert result["iss"] == _thumbprint(cnf_jwk)


def test_validate_oauth_client_attestation_pop_invalid_iss(
    cnf_jwk, wallet_instance_key
):
    payload = {"iss": "not-the-thumbprint", "exp": 9999999999}
    pop = JWS(json.dumps(payload), alg="ES256").sign_compact(
        [wallet_instance_key], protected={"alg": "ES256", "typ": "JWT"}
    )
    context = _context(**{OAUTH_CLIENT_ATTESTATION_POP_HEADER: pop})
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation_pop(
            context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER),
            cnf_jwk,
            ["ES256"],
        )


@pytest.mark.parametrize("client_attestation_pop", ["", None])
def test_validate_oauth_client_attestation_pop_missing(
    client_attestation_pop, cnf_jwk
):
    context = _context(
        **{OAUTH_CLIENT_ATTESTATION_POP_HEADER: client_attestation_pop}
    )
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation_pop(
            context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER),
            cnf_jwk,
            ["ES256"],
        )


def test_validate_oauth_client_attestation_pop_invalid_structure(cnf_jwk):
    context = _context(**{OAUTH_CLIENT_ATTESTATION_POP_HEADER: "not-a-jwt"})
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation_pop(
            context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER),
            cnf_jwk,
            ["ES256"],
        )
