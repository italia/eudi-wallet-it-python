import pytest

from pyeudiw.satosa.frontends.openid4vci.models.authorization_request import (
    AuthorizationRequest,
    CLIENT_ID_CTX,
    PAR_REQUEST_URI_CTX
)
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import ENDPOINT_CTX
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidRequestException


@pytest.fixture
def valid_context():
    return {
        ENDPOINT_CTX: "authorization",
        CLIENT_ID_CTX: "client-123",
        PAR_REQUEST_URI_CTX: "urn:ietf:params:oauth:request_uri:abc123"
    }

@pytest.mark.parametrize("client_id", ["", "  ", None])
def test_authorization_request_empty_or_missing_client_id(valid_context, client_id):
    payload = {
        "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
    }
    if client_id is not None:
        payload["client_id"] = client_id

    with pytest.raises(InvalidRequestException, match="missing `client_id` parameter"):
        AuthorizationRequest.model_validate(payload, context=valid_context)

@pytest.mark.parametrize("request_uri", ["", "  ", None])
def test_authorization_request_empty_or_missing_request_uri(valid_context, request_uri):
    payload = {
        "client_id": "client-123",
    }
    if request_uri is not None:
        payload["request_uri"] = request_uri

    with pytest.raises(InvalidRequestException, match="missing `request_uri` parameter"):
        AuthorizationRequest.model_validate(payload, context=valid_context)

@pytest.mark.parametrize("client_id", [
    "client123",
    " client123 ",
    "client123 ",
    " client123"
])
def test_authorization_request_invalid_client_id(valid_context,  client_id):
    payload = {
        "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
        "client_id": client_id
    }
    with pytest.raises(InvalidRequestException, match="invalid `client_id` parameter"):
        AuthorizationRequest.model_validate(payload, context=valid_context)

@pytest.mark.parametrize("request_uri", [
    "urn:ietf:params:oauth:request_uri:abc ",
    " urn:ietf:params:oauth:request_uri:abc ",
    " urn:ietf:params:oauth:request_uri:abc",
    "urn:ietf:params:oauth:request_uri:abc",
])
def test_authorization_request_invalid_request_uri(valid_context, request_uri):
    payload = {
        "request_uri": request_uri,
        "client_id": "client-123"
    }
    with pytest.raises(InvalidRequestException, match="invalid `request_uri` parameter"):
        AuthorizationRequest.model_validate(payload, context=valid_context)

