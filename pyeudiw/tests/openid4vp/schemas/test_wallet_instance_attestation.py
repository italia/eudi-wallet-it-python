import pytest
from pydantic import ValidationError

from pyeudiw.openid4vp.schemas.wallet_instance_attestation import WalletInstanceAttestationHeader, \
    WalletInstanceAttestationPayload

WALLET_INSTANCE_ATTESTATION = {
    "header": {
        "alg": "RS256",
        "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
        "trust_chain": [
            "eyJhbGciOiJFUz...6S0A",
            "eyJhbGciOiJFUz...jJLA",
            "eyJhbGciOiJFUz...H9gw",
        ],
        "typ": "wallet-attestation+jwt",
        "x5c": ["MIIBjDCC ... XFehgKQA=="]
    },
    "payload": {
        "iss": "https://wallet-provider.example.org",
        "sub": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
        "type": "WalletInstanceAttestation",
        "policy_uri": "https://wallet-provider.example.org/privacy_policy",
        "tos_uri": "https://wallet-provider.example.org/info_policy",
        "logo_uri": "https://wallet-provider.example.org/logo.svg",
        "attested_security_context": "https://wallet-provider.example.org/LoA/basic",
        "cnf": {
            "jwk": {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "x5c": [
                    "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
                ],
                "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
                "e": "AQAB",
                "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
                "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
            }
        },
        "authorization_endpoint": "eudiw:",
        "response_types_supported": [
            "vp_token"
        ],
        "vp_formats_supported": {
            "jwt_vp_json": {
                "alg_values_supported": ["RS256"]
            },
            "jwt_vc_json": {
                "alg_values_supported": ["RS256"]
            }
        },
        "request_object_signing_alg_values_supported": [
            "RS256"
        ],
        "presentation_definition_uri_supported": False,
        "iat": 1687281195,
        "exp": 1687288395
    }
}


def test_header():
    WalletInstanceAttestationHeader(**WALLET_INSTANCE_ATTESTATION['header'])
    # alg is RS256
    # it should fail if alg is not in supported_algorithms
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader.model_validate(
            WALLET_INSTANCE_ATTESTATION['header'], context={"supported_algorithms": None})
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader.model_validate(
            WALLET_INSTANCE_ATTESTATION['header'], context={"supported_algorithms": []})
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader.model_validate(
            WALLET_INSTANCE_ATTESTATION['header'], context={"supported_algorithms": ["asd"]})

    WalletInstanceAttestationHeader.model_validate(
        WALLET_INSTANCE_ATTESTATION['header'], context={"supported_algorithms": ["RS256"]})

    # x5c and trust_chain are not required
    WALLET_INSTANCE_ATTESTATION['header']['x5c'] = None
    WALLET_INSTANCE_ATTESTATION['header']['trust_chain'] = None
    WalletInstanceAttestationHeader(**WALLET_INSTANCE_ATTESTATION['header'])
    del WALLET_INSTANCE_ATTESTATION['header']['x5c']
    del WALLET_INSTANCE_ATTESTATION['header']['trust_chain']
    WalletInstanceAttestationHeader(**WALLET_INSTANCE_ATTESTATION['header'])

    # kid is required
    WALLET_INSTANCE_ATTESTATION['header']['kid'] = None
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(
            **WALLET_INSTANCE_ATTESTATION['header'])
    del WALLET_INSTANCE_ATTESTATION['header']['kid']
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(
            **WALLET_INSTANCE_ATTESTATION['header'])

    # typ must be "wallet-attestation-jwt"
    WALLET_INSTANCE_ATTESTATION['header']['typ'] = "asd"
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(
            **WALLET_INSTANCE_ATTESTATION['header'])


def test_payload():
    WalletInstanceAttestationPayload(**WALLET_INSTANCE_ATTESTATION['payload'])
    WalletInstanceAttestationPayload.model_validate(
        WALLET_INSTANCE_ATTESTATION['payload'])

    # iss is not HttpUrl
    WALLET_INSTANCE_ATTESTATION['payload']['iss'] = WALLET_INSTANCE_ATTESTATION['payload']['iss'][4:]
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION['payload'])
    WALLET_INSTANCE_ATTESTATION['payload']['iss'] = "http" + \
        WALLET_INSTANCE_ATTESTATION['payload']['iss']
    WalletInstanceAttestationPayload.model_validate(
        WALLET_INSTANCE_ATTESTATION['payload'])

    # empty cnf
    cnf = WALLET_INSTANCE_ATTESTATION['payload']['cnf']
    WALLET_INSTANCE_ATTESTATION['payload']['cnf'] = {}
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION['payload'])
    del WALLET_INSTANCE_ATTESTATION['payload']['cnf']
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION['payload'])
    WALLET_INSTANCE_ATTESTATION['payload']['cnf'] = cnf

    # cnf jwk is not a JWK
    WALLET_INSTANCE_ATTESTATION['payload']['cnf']['jwk'] = {}
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION['payload'])
