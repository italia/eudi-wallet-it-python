import pytest
from pydantic import ValidationError

from pyeudiw.federation.schemas.entity_configuration import (
    EntityConfigurationHeader,
    EntityConfigurationPayload,
)

ENTITY_CONFIGURATION = {
    "header": {
        "alg": "RS256",
        "kid": "2HnoFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMEEs",
        "typ": "entity-statement+jwt",
    },
    "payload": {
        "exp": 1649590602,
        "iat": 1649417862,
        "iss": "https://rp.example.it",
        "sub": "https://rp.example.it",
        "jwks": {
            "keys": [
                {
                    "kty": "RSA",
                    "n": "5s4qi …",
                    "e": "AQAB",
                    "kid": "2HnoFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMEEs",
                }
            ]
        },
        "metadata": {
            "openid_credential_verifier": {
                "application_type": "web",
                "client_id": "https://rp.example.it",
                "client_name": "Name of an example organization",
                "jwks": {
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "n": "1Ta-sE …",
                            "e": "AQAB",
                            "kid": "YhNFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMEEs",
                            "x5c": ["..."],
                        }
                    ]
                },
                "contacts": ["ops@verifier.example.org"],
                "request_uris": ["https://verifier.example.org/request_uri"],
                "redirect_uris": ["https://verifier.example.org/callback"],
                "default_acr_values": [
                    "https://www.spid.gov.it/SpidL2",
                    "https://www.spid.gov.it/SpidL3",
                ],
                "vp_formats": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["ES256", "ES384"],
                        "kb-jwt_alg_values": ["ES256", "ES384"],
                    }
                },
                "default_max_age": 1111,
                "authorization_signed_response_alg": ["RS256", "ES256"],
                "authorization_encrypted_response_alg": ["RSA-OAEP", "RSA-OAEP-256"],
                "authorization_encrypted_response_enc": [
                    "A128CBC-HS256",
                    "A192CBC-HS384",
                    "A256CBC-HS512",
                    "A128GCM",
                    "A192GCM",
                    "A256GCM",
                ],
                "subject_type": "pairwise",
                "require_auth_time": True,
                "id_token_signed_response_alg": ["RS256", "ES256"],
                "id_token_encrypted_response_alg": ["RSA-OAEP", "RSA-OAEP-256"],
                "id_token_encrypted_response_enc": [
                    "A128CBC-HS256",
                    "A192CBC-HS384",
                    "A256CBC-HS512",
                    "A128GCM",
                    "A192GCM",
                    "A256GCM",
                ],
            },
            "federation_entity": {
                "organization_name": "OpenID Wallet Verifier example",
                "homepage_uri": "https://verifier.example.org/home",
                "policy_uri": "https://verifier.example.org/policy",
                "logo_uri": "https://verifier.example.org/static/logo.svg",
                "contacts": ["tech@verifier.example.org"],
            },
        },
        "authority_hints": ["https://registry.eudi-wallet.example.it"],
    },
}


def test_entity_configuration_header():
    EntityConfigurationHeader(**ENTITY_CONFIGURATION["header"])

    with pytest.raises(ValidationError):
        EntityConfigurationHeader.model_validate(
            ENTITY_CONFIGURATION["header"], context={"supported_algorithms": ["ES256"]}
        )

    ENTITY_CONFIGURATION["header"]["typ"] = "NOT-entity-statement+jwt"
    with pytest.raises(ValidationError):
        EntityConfigurationHeader(**ENTITY_CONFIGURATION["header"])


def test_entity_configuration_payload():
    EntityConfigurationPayload(**ENTITY_CONFIGURATION["payload"])

    ENTITY_CONFIGURATION["payload"]["jwks"]["keys"] = []
    EntityConfigurationPayload(**ENTITY_CONFIGURATION["payload"])
    del ENTITY_CONFIGURATION["payload"]["jwks"]["keys"]
    with pytest.raises(ValidationError):
        EntityConfigurationPayload(**ENTITY_CONFIGURATION["payload"])

    ENTITY_CONFIGURATION["payload"]["jwks"]["keys"] = [
        {
            "kty": "RSA",
            "n": "5s4qi …",
            "e": "AQAB",
            "kid": "2HnoFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMEEs",
        }
    ]
