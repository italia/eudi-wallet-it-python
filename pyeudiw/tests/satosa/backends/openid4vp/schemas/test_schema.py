import pytest
from pydantic import ValidationError

from pyeudiw.federation.schemas.entity_configuration import (
    EntityConfigurationHeader,
    EntityConfigurationPayload,
)
from pyeudiw.satosa.backends.openid4vp.schemas.wallet_instance_attestation_request import (
    WalletInstanceAttestationRequestHeader,
    WalletInstanceAttestationRequestPayload,
)


def test_wir():
    wir_dict = {
        "header": {
            "alg": "RS256",
            "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
            "typ": "var+jwt",
        },
        "payload": {
            "iss": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
            "aud": "https://wallet-provider.example.org",
            "jti": "6ec69324-60a8-4e5b-a697-a766d85790ea",
            "type": "WalletInstanceAttestationRequest",
            "nonce": ".....",
            "cnf": {
                "jwk": {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "x5c": [
                        "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4"
                        "MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y3"
                        "1P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/sk"
                        "MCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCX"
                        "YdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZI"
                        "hvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57"
                        "F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbP"
                        "YBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
                    ],
                    "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei"
                    "6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIA"
                    "RRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
                    "e": "AQAB",
                    "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
                    "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
                }
            },
            "iat": 1686645115,
            "exp": 1686652315,
        },
    }

    WalletInstanceAttestationRequestHeader(**wir_dict["header"])
    WalletInstanceAttestationRequestPayload(**wir_dict["payload"])

    WalletInstanceAttestationRequestHeader.model_validate(
        wir_dict["header"], context={"supported_algorithms": ["RS256"]}
    )
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestHeader.model_validate(
            wir_dict["header"], context={"supported_algorithms": []}
        )
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestHeader.model_validate(
            wir_dict["header"], context={"supported_algorithms": None}
        )
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestHeader.model_validate(
            wir_dict["header"], context={"supported_algorithms": ["RS384"]}
        )

    wir_dict["payload"]["type"] = "NOT_WalletInstanceAttestationRequest"
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestPayload.model_validate(
            wir_dict["payload"], context={"supported_algorithms": ["RS256"]}
        )
    wir_dict["payload"]["type"] = "WalletInstanceAttestationRequest"

    wir_dict["payload"]["cnf"] = {"wrong_name_jwk": wir_dict["payload"]["cnf"]["jwk"]}
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestPayload.model_validate(
            wir_dict["payload"], context={"supported_algorithms": ["RS256"]}
        )
    wir_dict["payload"]["cnf"] = {"jwk": wir_dict["payload"]["cnf"]["wrong_name_jwk"]}


def test_entity_config_header():
    header = {
        "alg": "RS256",
        "kid": "2HnoFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMEEs",
        "typ": "entity-statement+jwt",
    }
    EntityConfigurationHeader(**header)

    header["typ"] = "entity-config+jwt"
    with pytest.raises(ValidationError):
        EntityConfigurationHeader(**header)
    header["typ"] = "entity-statement+jwt"

    with pytest.raises(ValidationError):
        EntityConfigurationHeader.model_validate(
            header, context={"supported_algorithms": []}
        )

    with pytest.raises(ValidationError):
        EntityConfigurationHeader.model_validate(
            header, context={"supported_algorithms": ["asd"]}
        )

    EntityConfigurationHeader.model_validate(
        header, context={"supported_algorithms": ["RS256"]}
    )


def test_entity_config_payload():
    payload = {
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
                "authorization_encrypted_response_alg": [
                    "RSA-OAEP",
                    "RSA-OAEP-256",
                    "ECDH-ES",
                ],
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
    }
    EntityConfigurationPayload(**payload)
