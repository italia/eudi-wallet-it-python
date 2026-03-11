import json
from copy import deepcopy

import pytest
from satosa.context import Context

from pyeudiw.jwt.utils import base64_urldecode
from pyeudiw.satosa.frontends.openid4vci.endpoints.metadata_endpoint import MetadataHandler
from pyeudiw.tests.satosa.frontends.openid4vci.endpoints.endpoints_test import do_test_missing_configurations_raises
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_ENDPOINTS_CONFIG,
    MOCK_JWT_CONFIG,
    MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG,
    MOCK_TRUST_CONFIG,
    MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG,
    MOCK_USER_STORAGE_CONFIG,
    MOCK_CREDENTIAL_STORAGE_CONFIG,
    MOCK_METADATA_JWKS_CONFIG,
    MOCK_CREDENTIAL_CONFIGURATIONS,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context,
)
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, APPLICATION_JSON, ENTITY_STATEMENT_JWT, get_content_type_header

# JWK parameter names that must never appear in published metadata (private key material).
PRIVATE_KEY_PARAMS = ("d", "p", "q", "dp", "dq", "qi")


def _get_entity_configuration_payload(metadata_handler: MetadataHandler, context: Context, *, as_json: bool) -> dict:
    """Return the entity configuration payload as a dict (from JSON response or decoded JWT)."""
    if as_json:
        context.qs_params = {"format": "json"}
        response = metadata_handler.endpoint(context)
        assert response.status == "200"
        return json.loads(response.message)
    context.qs_params = {"format": "jwt"}
    response = metadata_handler.endpoint(context)
    assert response.status == "200"
    jwt_parts = response.message.split(".")
    return json.loads(base64_urldecode(jwt_parts[1]))


def _collect_all_jwk_dicts_from_entity_config(payload: dict) -> list[dict]:
    """Collect every JWK dict from entity configuration (top-level jwks and metadata.*.jwks)."""
    keys_list: list[dict] = []
    if "jwks" in payload and isinstance(payload["jwks"], dict) and "keys" in payload["jwks"]:
        keys_list.extend(payload["jwks"]["keys"])
    for metadata_val in payload.get("metadata", {}).values():
        if isinstance(metadata_val, dict) and "jwks" in metadata_val and isinstance(metadata_val["jwks"], dict):
            keys_list.extend(metadata_val["jwks"].get("keys", []))
    return keys_list


def _assert_no_private_key_material(jwk_dict: dict) -> None:
    """Assert that the JWK dict contains no private key parameters."""
    for param in PRIVATE_KEY_PARAMS:
        assert param not in jwk_dict, f"Private key parameter {param!r} must not appear in published metadata"


@pytest.fixture
def metadata_handler() -> MetadataHandler:
    return MetadataHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)


@pytest.fixture
def context() -> Context:
    return get_mocked_satosa_context(method="GET", headers={HTTP_CONTENT_TYPE_HEADER: APPLICATION_JSON})


_DEFAULT_ISSUER_FROM_STANDARD_CONFIG = {
    "openid_credential_issuer": f"{MOCK_BASE_URL}/{MOCK_NAME}",
    "oauth_authorization_server_issuer": f"{MOCK_BASE_URL}/{MOCK_NAME}",
}


def _mock_configurations(field: list[str] | str):
    config = {
        "endpoints": MOCK_ENDPOINTS_CONFIG,
        "jwt": MOCK_JWT_CONFIG,
        "metadata": {"oauth_authorization_server": MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG, "openid_credential_issuer": MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG},
        "user_storage": MOCK_USER_STORAGE_CONFIG,
        "credential_storage": MOCK_CREDENTIAL_STORAGE_CONFIG,
        "metadata_jwks": MOCK_METADATA_JWKS_CONFIG,
        "trust": MOCK_TRUST_CONFIG,
    }
    if field != "credential_configurations":
        credential_configurations = deepcopy(MOCK_CREDENTIAL_CONFIGURATIONS)
        [credential_configurations.pop(f, None) for f in ([field] if isinstance(field, str) else field)]
        config["credential_configurations"] = credential_configurations
    return config


@pytest.mark.parametrize(
    "config, missing_fields",
    [
        (_mock_configurations("credential_configurations"), ["credential_configurations"]),
    ],
)
def test_missing_configurations(config, missing_fields):
    do_test_missing_configurations_raises(MetadataHandler, config, missing_fields)


def test_endpoint_returns_json_with_ensured_credential_issuer(metadata_handler, context):
    _run_endpoint_returns_json_test(metadata_handler, context, _DEFAULT_ISSUER_FROM_STANDARD_CONFIG)


def test_endpoint_returns_json_with_config_credential_issuer(context):
    context.qs_params = {"format": "json"}
    config = deepcopy(MOCK_PYEUDIW_FRONTEND_CONFIG)
    config["metadata"]["openid_credential_issuer"]["credential_issuer"] = "config-credential-issuer"
    metadata_handler = MetadataHandler(config, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    _run_endpoint_returns_json_test(
        metadata_handler, context, {"openid_credential_issuer": "config-credential-issuer", "oauth_authorization_server_issuer": f"{MOCK_BASE_URL}/{MOCK_NAME}"}
    )


def test_endpoint_returns_jwt(metadata_handler, context):
    context.qs_params = {"format": "jwt"}
    response = metadata_handler.endpoint(context)
    assert response.status == "200"
    assert get_content_type_header(response.headers) == ENTITY_STATEMENT_JWT
    jwt_parts = response.message.split(".")
    header = json.loads(base64_urldecode(jwt_parts[0]))
    assert header["alg"] == "ES256"
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


@pytest.mark.parametrize("as_json", [True, False])
def test_entity_configuration_jwks_contain_no_private_keys(metadata_handler, context, as_json: bool):
    """All JWKs in published entity configuration must be public only; private key material must never be exposed."""
    payload = _get_entity_configuration_payload(metadata_handler, context, as_json=as_json)
    for jwk_dict in _collect_all_jwk_dicts_from_entity_config(payload):
        _assert_no_private_key_material(jwk_dict)


def test_entity_configuration_federation_jwks_count_and_public_only(metadata_handler, context):
    """Entity configuration jwks.keys must contain exactly the configured federation keys, and only in public form."""
    payload = _get_entity_configuration_payload(metadata_handler, context, as_json=True)
    expected_count = len(
        MOCK_PYEUDIW_FRONTEND_CONFIG["trust"]["federation"]["config"].get("federation_jwks", [])
    )
    assert "jwks" in payload and "keys" in payload["jwks"]
    entity_keys = payload["jwks"]["keys"]
    assert len(entity_keys) == expected_count, (
        f"Expected {expected_count} federation public key(s) in entity jwks, got {len(entity_keys)}"
    )
    for jwk_dict in entity_keys:
        _assert_no_private_key_material(jwk_dict)


def test_metadata_credential_issuer_jwks_contain_no_private_keys_when_config_has_jwks(context):
    """When config metadata contains jwks (with private keys), published metadata must expose only public keys."""
    config = deepcopy(MOCK_PYEUDIW_FRONTEND_CONFIG)
    # Use keys that include private material (e.g. "d"); endpoint must publish only public form.
    config["metadata"]["openid_credential_issuer"]["jwks"] = MOCK_METADATA_JWKS_CONFIG
    metadata_handler = MetadataHandler(config, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
    payload = _get_entity_configuration_payload(metadata_handler, context, as_json=True)
    for jwk_dict in _collect_all_jwk_dicts_from_entity_config(payload):
        _assert_no_private_key_material(jwk_dict)
