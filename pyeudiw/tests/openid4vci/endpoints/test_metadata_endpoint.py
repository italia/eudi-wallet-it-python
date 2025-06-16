import json
from copy import deepcopy

import pytest
from satosa.context import Context

from pyeudiw.jwt.utils import base64_urldecode
from pyeudiw.openid4vci.endpoints.metadata_endpoint import MetadataHandler
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON,
    ENTITY_STATEMENT_JWT,
    get_content_type_header
)


@pytest.fixture
def metadata_handler() -> MetadataHandler:
    return MetadataHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)

@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(
        method="GET",
        headers = {
            HTTP_CONTENT_TYPE_HEADER: APPLICATION_JSON
        }
    )

_DEFAULT_ISSUER_FROM_STANDARD_CONFIG = {
    "openid_credential_issuer": f"{MOCK_BASE_URL}/{MOCK_NAME}",
    "oauth_authorization_server_issuer": f"{MOCK_BASE_URL}/{MOCK_NAME}"
}

def test_endpoint_returns_json_with_ensured_credential_issuer(metadata_handler, context):
    _run_endpoint_returns_json_test(metadata_handler, context, _DEFAULT_ISSUER_FROM_STANDARD_CONFIG)

def test_endpoint_returns_json_with_config_credential_issuer(context):
    context.qs_params = {"format": "json"}
    config = deepcopy(MOCK_PYEUDIW_FRONTEND_CONFIG)
    config["metadata"]["openid_credential_issuer"]["credential_issuer"] = "config-credential-issuer"
    metadata_handler = MetadataHandler(config, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    _run_endpoint_returns_json_test(metadata_handler, context, {
        "openid_credential_issuer": "config-credential-issuer",
        "oauth_authorization_server_issuer": f"{MOCK_BASE_URL}/{MOCK_NAME}"
    })

def test_endpoint_returns_jwt(metadata_handler, context):
    context.qs_params = {"format": "jwt"}
    response = metadata_handler.endpoint(context)
    assert response.status == "200"
    assert get_content_type_header(response.headers) == ENTITY_STATEMENT_JWT
    jwt_parts = response.message.split('.')
    header = json.loads(base64_urldecode(jwt_parts[0]))
    assert header["alg"] == MOCK_PYEUDIW_FRONTEND_CONFIG["credential_configurations"]["entity_default_sig_alg"]
    assert header["kid"] == MOCK_PYEUDIW_FRONTEND_CONFIG["metadata_jwks"][0]["kid"]
    assert header["typ"] == "entity-statement+jwt"

    payload = json.loads(base64_urldecode(jwt_parts[1]))
    _assert_metadata(MOCK_PYEUDIW_FRONTEND_CONFIG, payload["metadata"], _DEFAULT_ISSUER_FROM_STANDARD_CONFIG)

def _run_endpoint_returns_json_test(metadata_handler, context, expected_issuer: dict):
    context.qs_params = {"format": "json"}
    response = metadata_handler.endpoint(context)
    assert response.status == "200"
    assert get_content_type_header(response.headers) == APPLICATION_JSON
    response_data = json.loads(response.message)
    _assert_metadata(metadata_handler.config, response_data["metadata"], expected_issuer)

def _assert_metadata(config: dict, response_metadata: dict, expected_issuer: dict):
    for k, v in config["metadata"].items():
        assert k in response_metadata
        assert response_metadata[k] == v
    assert response_metadata["openid_credential_issuer"]["credential_issuer"] == expected_issuer["openid_credential_issuer"]
    assert response_metadata["oauth_authorization_server"]["issuer"] == expected_issuer["oauth_authorization_server_issuer"]