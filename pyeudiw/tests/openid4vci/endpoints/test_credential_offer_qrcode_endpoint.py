from unittest.mock import patch

import pytest
from satosa.context import Context

from pyeudiw.openid4vci.endpoints.credential_offer_qrcode_endpoint import CredentialOfferQrCodeHandler
from pyeudiw.tests.openid4vci.endpoints.endpoints_test import (
    do_test_missing_configurations_raises,
    do_test_invalid_request_method,
    do_test_invalid_content_type
)
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON,
    INVALID_METHOD_FOR_GET_REQ,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    mock_deserialized_overridable,
    get_mocked_satosa_context, REMOVE
)
from pyeudiw.tools.content_type import (
    APPLICATION_JSON
)


@pytest.fixture
def credential_offer_qrcode_handler() -> CredentialOfferQrCodeHandler:
    with patch("pyeudiw.openid4vci.endpoints.credential_offer_qrcode_endpoint.Jinja2TemplateHandler") as MockTemplateHandler:
        return CredentialOfferQrCodeHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(method = "GET", content_type = APPLICATION_JSON)

def _mock_configurations(overrides=None):
    return mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, overrides)

@pytest.mark.parametrize("config, missing_fields", [
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"qrcode": REMOVE}), ["qrcode"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"qrcode.size": REMOVE}), ["qrcode.size"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"qrcode.color": REMOVE}), ["qrcode.color"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"qrcode.expiration_time": REMOVE}), ["qrcode.expiration_time"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"qrcode.logo_path": REMOVE}), ["qrcode.logo_path"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"qrcode.ui_template": REMOVE}), ["qrcode.ui_template"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"credential_configurations": REMOVE}), ["credential_configurations"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"credential_configurations.status_list": REMOVE}), ["credential_configurations.status_list"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG,{"credential_configurations.status_list.path": REMOVE}), ["credential_configurations.status_list.path"]),
])
def test_missing_configurations(config, missing_fields):
    do_test_missing_configurations_raises(CredentialOfferQrCodeHandler, config, missing_fields)

@pytest.mark.parametrize("method", INVALID_METHOD_FOR_GET_REQ)
def test_invalid_request_method(credential_offer_qrcode_handler, context, method):
    do_test_invalid_request_method(credential_offer_qrcode_handler, context, method)

@pytest.mark.parametrize("content_type", INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON)
def test_invalid_content_type(credential_offer_qrcode_handler, context, content_type):
    do_test_invalid_content_type(credential_offer_qrcode_handler, context, content_type)

