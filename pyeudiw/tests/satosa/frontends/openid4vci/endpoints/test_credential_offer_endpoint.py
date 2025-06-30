from copy import deepcopy

import pytest
from satosa.context import Context

from pyeudiw.satosa.frontends.openid4vci.endpoints.credential_offer_endpoint import CredentialOfferHandler
from pyeudiw.tests.satosa.frontends.openid4vci.endpoints.endpoints_test import (
    do_test_missing_configurations_raises,
    do_test_invalid_request_method,
    do_test_invalid_content_type
)
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON,
    INVALID_METHOD_FOR_GET_REQ,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG,
    MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG,
    MOCK_NAME,
    MOCK_BASE_URL,
    mock_deserialized_overridable,
    get_mocked_satosa_context
)
from pyeudiw.tools.content_type import (
    APPLICATION_JSON
)


@pytest.fixture
def credential_offer_handler() -> CredentialOfferHandler:
    return CredentialOfferHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(method = "GET", content_type = APPLICATION_JSON)

def _mock_configurations(overrides=None):
    return mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, overrides)

_removed_credential_configurations_supported = { k: v for k, v in deepcopy(MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG).items() if k != "credential_configurations_supported" }
@pytest.mark.parametrize("config, missing_fields", [
    (_mock_configurations({"metadata": {"openid_credential_issuer": MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG}}), ["metadata.oauth_authorization_server"]),
    (_mock_configurations({"metadata": {"oauth_authorization_server": MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG, "openid_credential_issuer": _removed_credential_configurations_supported}}), ["metadata.openid_credential_issuer.credential_configurations_supported"]),
])
def test_missing_configurations(config, missing_fields):
    do_test_missing_configurations_raises(CredentialOfferHandler, config, missing_fields)

@pytest.mark.parametrize("method", INVALID_METHOD_FOR_GET_REQ)
def test_invalid_request_method(credential_offer_handler, context, method):
    do_test_invalid_request_method(credential_offer_handler, context, method)

@pytest.mark.parametrize("content_type", INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON)
def test_invalid_content_type(credential_offer_handler, context, content_type):
    do_test_invalid_content_type(credential_offer_handler, context, content_type)

