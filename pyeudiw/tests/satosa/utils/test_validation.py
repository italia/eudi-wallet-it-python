import json

import pytest
from cryptojwt import JWS
from cryptojwt.jwk.ec import new_ec_key
from satosa.context import Context

from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method,
    validate_oauth_client_attestation
)
from pyeudiw.tools.content_type import FORM_URLENCODED, APPLICATION_JSON
from pyeudiw.tools.exceptions import InvalidRequestException


@pytest.fixture
def valid_oauth_client_attestation_jwt():
    ec_key = new_ec_key(crv="P-256", use="sig", kid="ec1")
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


def test_validate_oauth_client_attestation_valid(valid_oauth_client_attestation_jwt):
    context = Context()
    context.http_headers = {
        "OAuth-Client-Attestation": valid_oauth_client_attestation_jwt,
        "OAuth-Client-Attestation-PoP": "header2"
    }
    result = validate_oauth_client_attestation(context)
    assert isinstance(result, dict)
    assert "thumbprint" in result
    assert result["thumbprint"]


@pytest.mark.parametrize("headers", [
    {"OAuth-Client-Attestation": "", "OAuth-Client-Attestation-PoP": "valid"},
    {"OAuth-Client-Attestation": None, "OAuth-Client-Attestation-PoP": "valid"},
    {"OAuth-Client-Attestation-PoP": "valid"},
    {"OAuth-Client-Attestation": "valid", "OAuth-Client-Attestation-PoP": ""},
    {"OAuth-Client-Attestation": "valid", "OAuth-Client-Attestation-PoP": None},
    {"OAuth-Client-Attestation": "valid"},
    {"OAuth-Client-Attestation": "", "OAuth-Client-Attestation-PoP": ""},
    {"OAuth-Client-Attestation": None, "OAuth-Client-Attestation-PoP": None},
    {}
])
def test_validate_oauth_client_attestation_invalid(headers):
    context = Context()
    context.http_headers = headers
    with pytest.raises(InvalidRequestException):
        validate_oauth_client_attestation(context)
