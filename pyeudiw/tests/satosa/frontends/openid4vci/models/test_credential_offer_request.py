import pytest

from pyeudiw.satosa.frontends.openid4vci.models.config import PyeudiwFrontendConfig
from pyeudiw.satosa.frontends.openid4vci.models.credential_offer_request import CredentialOfferRequest
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import CONFIG_CTX
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidRequestException
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import MOCK_PYEUDIW_FRONTEND_CONFIG


def get_valid_context(authorization_servers =[]):
    MOCK_PYEUDIW_FRONTEND_CONFIG["metadata"]["openid_credential_issuer"]["authorization_servers"] = authorization_servers
    return {
        CONFIG_CTX: PyeudiwFrontendConfig(**MOCK_PYEUDIW_FRONTEND_CONFIG)
    }

@pytest.mark.parametrize("credential_issuer", ["", "  ", None])
def test_empty_or_missing_credential_issuer(credential_issuer):
    payload = {}
    if credential_issuer is not None:
        payload["credential_issuer"] = credential_issuer

    with pytest.raises(InvalidRequestException, match="missing `credential_issuer` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("credential_issuer", [
    ":",           # invalid URL
    "noscheme.com",# no scheme
    "ftp://",      # no netloc or path
    "http:///path", # missing netloc but has path, may be valid, test anyway
    "https://example.com" #missing path
])
def test_invalid_credential_issuer(credential_issuer):
    payload = {"credential_issuer": credential_issuer}
    with pytest.raises(InvalidRequestException, match="invalid `credential_issuer` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("credential_configuration_ids", [
    [],
    None,
])
def test_empty_or_missing_credential_configuration_ids(credential_configuration_ids):
    payload = {
        "credential_issuer": "https://example.com/my-path"
    }
    if credential_configuration_ids is not None:
        payload["credential_configuration_ids"] = credential_configuration_ids

    with pytest.raises(InvalidRequestException, match="missing `credential_configuration_ids` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("credential_configuration_ids", [
    [" ", ""],
    ["", "pippo"],
    ["test", "eudiw.pda1.se"],
    [""],
])
def test_invalid_credential_configuration_ids(credential_configuration_ids):
    payload = {
        "credential_issuer": "https://example.com/my-path"
    }
    if credential_configuration_ids is not None:
        payload["credential_configuration_ids"] = credential_configuration_ids

    with pytest.raises(InvalidRequestException, match="invalid `credential_configuration_ids` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context())

def test_missing_grants():
    payload = {
        "credential_issuer": "https://example.com/my-path",
        "credential_configuration_ids": ["dc_sd_jwt_EuropeanDisabilityCard"]
    }

    with pytest.raises(InvalidRequestException, match="missing `grants` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context())

@pytest.mark.parametrize("authorization_server", ["", " ", None])
def test_missing_grants_authorization_server(authorization_server):
    grants = {
        "issuer_state": "issuer_state_test"
    }
    if authorization_server is not None:
        grants["authorization_server"] = authorization_server

    payload = {
        "credential_issuer": "https://example.com/my-path",
        "credential_configuration_ids": ["eudiw.pda1.se"],
        "grants": grants
    }

    with pytest.raises(InvalidRequestException, match="missing `grants.authorization_server` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context())

def test_invalid_grants_authorization_server():
    payload = {
        "credential_issuer": "https://example.com/my-path",
        "credential_configuration_ids": ["eudiw.pda1.se"],
        "grants": {
            "issuer_state": "issuer_state_test",
            "authorization_server": "server"
        }
    }
    with pytest.raises(InvalidRequestException, match="invalid `grants.authorization_server` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context(authorization_servers=["myserver"]))

def test_invalid_grants_authorization_server_when_not_expected():
    payload = {
        "credential_issuer": "https://example.com/my-path",
        "credential_configuration_ids": ["eudiw.pda1.se"],
        "grants": {
            "issuer_state": "issuer_state_test",
            "authorization_server": "server"
        }
    }
    with pytest.raises(InvalidRequestException, match="invalid `grants.authorization_server` parameter"):
        CredentialOfferRequest.model_validate(payload, context=get_valid_context())

def test_valid_credential_offer_request():
    payload = {
        "credential_issuer": "https://example.com/my-path",
        "credential_configuration_ids": ["dc_sd_jwt_EuropeanDisabilityCard"],
        "grants": {
            "issuer_state": "issuer_state_test",
            "authorization_server": "server"
        }
    }
    CredentialOfferRequest.model_validate(payload, context=get_valid_context(authorization_servers=["server"]))