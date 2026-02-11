import json

import pytest
from cryptojwt import JWS
from cryptojwt.jwk.ec import new_ec_key
from satosa.context import Context

from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.utils.validation import (
    OAUTH_CLIENT_ATTESTATION_HEADER,
    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
    validate_content_type,
    validate_request_method,
    validate_oauth_client_attestation,
    validate_oauth_client_attestation_pop,
)
from pyeudiw.tools.content_type import FORM_URLENCODED, APPLICATION_JSON


@pytest.fixture
def valid_oauth_client_attestation_jwt():
    ec_key = new_ec_key(crv="P-256", use="sig", kid="ec1", alg="ES256")
    payload = {"cnf": ec_key.serialize(private=False)}
    jws = JWS(json.dumps(payload), alg="ES256")
    return jws.sign_compact([ec_key])


def test_validate_content_type_form_urlencoded_valid():
    validate_content_type("application/x-www-form-urlencoded", FORM_URLENCODED)


def test_validate_content_type_form_urlencoded_invalid():
    with pytest.raises(InvalidRequestException):
        validate_content_type("text/plain", FORM_URLENCODED)


def test_validate_content_type_application_json_valid():
    validate_content_type("application/json", APPLICATION_JSON)


def test_validate_content_type_application_json_invalid():
    with pytest.raises(InvalidRequestException):
        validate_content_type("application/xml", APPLICATION_JSON)


@pytest.mark.parametrize("method", ["POST", "GET"])
def test_validate_request_method_valid(method):
    validate_request_method(method, ["GET", "POST"])


@pytest.mark.parametrize("method", [None, "DELETE", ""])
def test_validate_request_method_invalid(method):
    with pytest.raises(InvalidRequestException):
        validate_request_method(method, ["GET", "POST"])


def test_validate_oauth_client_attestation_valid_without_dpop_signing_alg_values_supported(valid_oauth_client_attestation_jwt):
    context = Context()
    context.http_headers = {OAUTH_CLIENT_ATTESTATION_HEADER: valid_oauth_client_attestation_jwt, OAUTH_CLIENT_ATTESTATION_POP_HEADER: "header2"}
    result = validate_oauth_client_attestation(context, None)
    assert isinstance(result, dict)
    assert "thumbprint" in result
    assert result["thumbprint"]


def test_validate_oauth_client_attestation_valid(valid_oauth_client_attestation_jwt):
    context = Context()
    context.http_headers = {OAUTH_CLIENT_ATTESTATION_HEADER: valid_oauth_client_attestation_jwt, OAUTH_CLIENT_ATTESTATION_POP_HEADER: "header2"}
    result = validate_oauth_client_attestation(context, ["ES256", "ES384", "ES512"])
    assert isinstance(result, dict)
    assert "thumbprint" in result
    assert result["thumbprint"]


def test_validate_oauth_client_attestation_valid_with_invalid_dpop_signing_alg_values_supported(valid_oauth_client_attestation_jwt):
    context = Context()
    context.http_headers = {OAUTH_CLIENT_ATTESTATION_HEADER: valid_oauth_client_attestation_jwt, OAUTH_CLIENT_ATTESTATION_POP_HEADER: "header2"}
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation(context, ["ES384", "ES512"])


def test_validate_oauth_client_attestation_pop_valid(valid_oauth_client_attestation_jwt):
    context = Context()
    context.http_headers = {OAUTH_CLIENT_ATTESTATION_HEADER: "header", OAUTH_CLIENT_ATTESTATION_POP_HEADER: valid_oauth_client_attestation_jwt}
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation_pop(context, ["ES384", "ES512"])


@pytest.mark.parametrize(
    "headers",
    [
        ({OAUTH_CLIENT_ATTESTATION_HEADER: "", OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid"}),
        ({OAUTH_CLIENT_ATTESTATION_HEADER: None, OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid"}),
        ({OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid"}),
        ({OAUTH_CLIENT_ATTESTATION_HEADER: "valid", OAUTH_CLIENT_ATTESTATION_POP_HEADER: ""}),
        ({OAUTH_CLIENT_ATTESTATION_HEADER: "valid", OAUTH_CLIENT_ATTESTATION_POP_HEADER: None}),
        ({OAUTH_CLIENT_ATTESTATION_HEADER: "valid"}),
        ({OAUTH_CLIENT_ATTESTATION_HEADER: "", OAUTH_CLIENT_ATTESTATION_POP_HEADER: ""}),
        ({OAUTH_CLIENT_ATTESTATION_HEADER: None, OAUTH_CLIENT_ATTESTATION_POP_HEADER: None}),
        ({}),
    ],
)
def test_validate_oauth_client_attestation_invalid(headers):
    context = Context()
    context.http_headers = headers
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation(context, None)
