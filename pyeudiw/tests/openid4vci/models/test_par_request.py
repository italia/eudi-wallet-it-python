import time
from uuid import uuid4

import pytest
import datetime

from pyeudiw.openid4vci.models.auhtorization_detail import OPEN_ID_CREDENTIAL_TYPE
from pyeudiw.openid4vci.models.authorization_request import CLIENT_ID_CTX
from pyeudiw.openid4vci.models.openid4vci_basemodel import (
    CONFIG_CTX,
    ENDPOINT_CTX,
    ENTITY_ID_CTX
)
from pyeudiw.openid4vci.models.par_request import ParRequest
from pyeudiw.satosa.schemas.config import PyeudiwFrontendConfig
from pyeudiw.tests.openid4vci.mock_openid4vci import MOCK_PYEUDIW_FRONTEND_CONFIG
from pyeudiw.tools.exceptions import InvalidRequestException


def get_valid_context():
    return {
        ENDPOINT_CTX: "par",
        CLIENT_ID_CTX: "client-123",
        ENTITY_ID_CTX: "entity-123",
        CONFIG_CTX: PyeudiwFrontendConfig(**MOCK_PYEUDIW_FRONTEND_CONFIG)
    }

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_iss(value):
    payload = {}
    if value is not None:
        payload["iss"] = value

    with pytest.raises(InvalidRequestException, match="missing `iss` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_iss_0", "  test_iss_1", "test_iss_2", " test_iss_3 "])
def test_invalid_iss(value):
    payload = {
        "iss": value
    }

    with pytest.raises(InvalidRequestException, match="invalid `iss` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_aud(value):
    payload = {
        "iss": "client-123"
    }
    if value is not None:
        payload["aud"] = value

    with pytest.raises(InvalidRequestException, match="missing `aud` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 "])
def test_invalid_aud(value):
    payload = {
        "iss": "client-123",
        "aud": value
    }

    with pytest.raises(InvalidRequestException, match="invalid `aud` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())


@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_state(value):
    payload = {
        "iss": "client-123",
        "aud": "entity-123"
    }
    if value is not None:
        payload["state"] = value

    with pytest.raises(InvalidRequestException, match="missing `state` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", [
    "short123", #too short
    "a" * 31 + "#", # not alnum
])
def test_invalid_state(value):
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": value
    }

    with pytest.raises(InvalidRequestException, match="invalid `state` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_client_id(value):
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32
    }
    if value is not None:
        payload["client_id"] = value

    with pytest.raises(InvalidRequestException, match="missing `client_id` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 "])
def test_invalid_client_id(value):
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": value
    }
    with pytest.raises(InvalidRequestException, match="invalid `client_id` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())


@pytest.mark.parametrize("value", [0, None])
def test_invalid_exp(value):
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
    }
    if value is not None:
        payload["exp"] = value

    with pytest.raises(InvalidRequestException, match="invalid `exp` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", [123, None])
def test_invalid_iat(value):
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "exp": int(time.time())
    }
    if value is not None:
        payload["iat"] = value

    with pytest.raises(InvalidRequestException, match="invalid `iat` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

def test_expired_token():
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now,
        "exp": now + 329
    }

    with pytest.raises(InvalidRequestException, match="expired token"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_response_type(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30
    }
    if value is not None:
        payload["response_type"] = value

    with pytest.raises(InvalidRequestException, match="missing `response_type` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())


@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 "])
def test_invalid_client_id(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": value
    }
    with pytest.raises(InvalidRequestException, match="invalid `response_type` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_response_mode(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code"
    }
    if value is not None:
        payload["response_mode"] = value

    with pytest.raises(InvalidRequestException, match="missing `response_mode` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 "])
def test_invalid_response_mode(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": value
    }
    with pytest.raises(InvalidRequestException, match="invalid `response_mode` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_code_challenge(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": "query"
    }
    if value is not None:
        payload["code_challenge"] = value

    with pytest.raises(InvalidRequestException, match="missing `code_challenge` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_code_challenge_method(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
    }
    if value is not None:
        payload["code_challenge_method"] = value

    with pytest.raises(InvalidRequestException, match="missing `code_challenge_method` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 "])
def test_invalid_code_challenge_method(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": value
    }

    with pytest.raises(InvalidRequestException, match="invalid `code_challenge_method` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_or_missing_scope(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
    }
    if value is not None:
        payload["scope"] = value

    with pytest.raises(InvalidRequestException, match="missing `scope` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 ", "scope1, pippo"])
def test_invalid_code_challenge_method(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": value
    }

    with pytest.raises(InvalidRequestException, match="invalid `scope` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", [None, []])
def test_empty_or_missing_authorization_details(value):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "redirect_uri": "https://client.example.org/cb",
        "jti": "client-123" + str(uuid4())
    }
    if value is not None:
        payload["authorization_details"] = value

    with pytest.raises(InvalidRequestException, match="missing `authorization_details` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_missing_authorization_details_type(value):
    authorization_details = {}
    if value is not None:
        authorization_details["type"] = value
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now +30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details]
    }

    with pytest.raises(InvalidRequestException, match="missing `authorization_details.type` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 "])
def test_invalid_authorization_details_type(value):
    authorization_details = {
        "type": value
    }
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details]
    }

    with pytest.raises(InvalidRequestException, match="invalid `authorization_details.type` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_missing_authorization_credential_configuration_id(value):
    authorization_details = {
        "type": OPEN_ID_CREDENTIAL_TYPE
    }
    if value is not None:
        authorization_details["credential_configuration_id"] = value
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details]
    }

    with pytest.raises(InvalidRequestException, match="missing `authorization_details.credential_configuration_id` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 "])
def test_invalid_authorization_details_credential_configuration_id(value):
    authorization_details = {
        "type": OPEN_ID_CREDENTIAL_TYPE,
        "credential_configuration_id": value
    }
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details]
    }

    with pytest.raises(InvalidRequestException, match="invalid `authorization_details.credential_configuration_id` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_missing_redirect_uri(value):
    authorization_details = {
        "type": OPEN_ID_CREDENTIAL_TYPE,
        "credential_configuration_id": "dc_sd_jwt_EuropeanDisabilityCard"
    }
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details]
    }
    if value is not None:
        payload["redirect_uri"] = value

    with pytest.raises(InvalidRequestException, match="missing `redirect_uri` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())


@pytest.mark.parametrize("value", [
    ":",           # invalid URL
    "noscheme.com",# no scheme
    "ftp://",      # no netloc or path
    "http:///path", # missing netloc but has path, may be valid, test anyway
    "https://example.com" #missing path
])
def test_invalid_redirect_uri(value):
    authorization_details = {
        "type": OPEN_ID_CREDENTIAL_TYPE,
        "credential_configuration_id": "dc_sd_jwt_EuropeanDisabilityCard"
    }
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details],
        "redirect_uri":value
    }

    with pytest.raises(InvalidRequestException, match="invalid `redirect_uri` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("value", ["", "  ", None])
def test_missing_jti(value):
    authorization_details = {
        "type": OPEN_ID_CREDENTIAL_TYPE,
        "credential_configuration_id": "dc_sd_jwt_EuropeanDisabilityCard"
    }
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details],
        "redirect_uri": "https://client.example.org/cb"
    }
    if value is not None:
        payload["jti"] = value

    with pytest.raises(InvalidRequestException, match="missing `jti` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())


@pytest.mark.parametrize("value", ["test_0", "  test_1", "test_2", " test_3 ", "client-123 ", "client-123"])
def test_invalid_jti(value):
    authorization_details = {
        "type": OPEN_ID_CREDENTIAL_TYPE,
        "credential_configuration_id": "dc_sd_jwt_EuropeanDisabilityCard"
    }
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "client-123",
        "aud": "entity-123",
        "state": "A" * 32,
        "client_id": "client-123",
        "iat": now + 29,
        "exp": now + 30,
        "response_type": "code",
        "response_mode": "query",
        "code_challenge": "code_challenge_test",
        "code_challenge_method": "S256",
        "scope": "scope1",
        "authorization_details": [authorization_details],
        "redirect_uri": "https://client.example.org/cb",
        "jti": value
    }

    with pytest.raises(InvalidRequestException, match="invalid `jti` parameter"):
        ParRequest.model_validate(payload, context=get_valid_context())