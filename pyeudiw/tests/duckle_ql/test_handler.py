from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pyeudiw.duckle_ql.handler import DuckleHandler
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

QUERY_CONFIG = {
    "presentation": [
        {"credentials[*].namespaces.org.iso.18013.5.1.given_name": "given_name"},
        {"credentials[*].namespaces.org.iso.18013.5.1.family_name": "family_name"}
    ],
    "query": [
        '{ "id": "mdl-id", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }, "claims": [ { "id": "given_name", "namespace": "org.iso.18013.5.1", "claim_name": "given_name" }, { "id": "family_name", "namespace": "org.iso.18013.5.1", "claim_name": "family_name" }, { "id": "resident_country", "namespace": "org.iso.18013.5.1", "claim_name": "resident_country", "values":["Italy"] }] }'
    ]
}

def create_test_token(query: dict) -> str:
    """Create a fake DCQL JWT token without signature verification for testing."""
    header = {"alg": "ES256", "typ": "dcql", "kid": "fake-kid"}
    token_payload = {
        "iss": "redirect_uri:https://client.example.org/cb",
        "jti": "66f336e2-2e5d-4816-812b-f11e16a01813",
        "iat": 1745817093,
        "exp": 1745817693,
        "nonce": "65144c50-9581-4334-8f56-6743b31b74d2",
        "sub": "https://localhost/OpenID4VP",
        "aud": "https://localhost/OpenID4VP",
        "dcql_query": query
    }
    private_key = ec.generate_private_key(ec.SECP256R1())

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return jwt.encode(token_payload, key=pem_private, algorithm="ES256", headers=header)

@pytest.fixture
def mock_trust_evaluator():
    return MagicMock(spec=CombinedTrustEvaluator)

def test_duckle_handler_parse_success(mock_trust_evaluator):
    token_payload = {
            "credentials": [
                {
                    "credential_format": "mso_mdoc",
                    "doctype": "org.iso.18013.5.1.mDL",
                    "namespaces": {
                        "org.iso.18013.5.1": {
                            "given_name": "Test",
                            "family_name": "User",
                            "resident_country": 'Italy',
                        }
                    }
                }
            ]
    }
    encoded_token = create_test_token(token_payload)

    handler = DuckleHandler(
        trust_evaluator=mock_trust_evaluator,
        **QUERY_CONFIG
    )
    handler.jwt = jwt

    result = handler.parse(encoded_token)

    assert result is not None
    assert isinstance(result, dict)
    assert result["given_name"] == "Test"
    assert result["family_name"] == "User"

def test_duckle_handler_parse_missing_dcql_query(mock_trust_evaluator):
    token_payload = {"some_other_key": "value"}
    encoded_token = create_test_token(token_payload)

    handler = DuckleHandler(trust_evaluator=mock_trust_evaluator)
    handler.jwt = jwt

    result = handler.parse(encoded_token)

    assert result is None

def test_duckle_handler_parse_missing_credentials(mock_trust_evaluator):
    token_payload = {"dcql_query": {"credentials": []}}
    encoded_token = create_test_token(token_payload)

    handler = DuckleHandler(trust_evaluator=mock_trust_evaluator)
    handler.jwt = jwt

    result = handler.parse(encoded_token)

    assert result is None
