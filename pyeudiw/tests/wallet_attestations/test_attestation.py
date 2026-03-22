import pytest
from pydantic import ValidationError

from pyeudiw.wallet_attestations import (
    WalletInstanceAttestationHeader,
    WalletInstanceAttestationPayload,
)

WALLET_INSTANCE_ATTESTATION = {
    "header": {
        "alg": "ES256",
        "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
        "trust_chain": [
            "eyJhbGciOiJFUz...6S0A",
            "eyJhbGciOiJFUz...jJLA",
            "eyJhbGciOiJFUz...H9gw",
        ],
        "typ": "oauth-client-attestation+jwt",  # OAUTH-ATTESTATION-CLIENT-AUTH (draft-ietf-oauth-attestation-based-client-auth)
        "x5c": ["MIIBjDCC ... XFehgKQA=="],
    },
    "payload": {
        "iss": "https://wallet-provider.example.org",
        "sub": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
        "type": "WalletInstanceAttestation",
        "policy_uri": "https://wallet-provider.example.org/privacy_policy",
        "tos_uri": "https://wallet-provider.example.org/info_policy",
        "logo_uri": "https://wallet-provider.example.org/logo.svg",
        "aal": "https://wallet-provider.example.org/LoA/basic",
        "cnf": {
            "jwk": {
                "alg": "ES256",
                "kty": "EC",
                "crv": "P-256",
                "use": "sig",
                "x": "VcKVNBZ4IaBAYW3jxM4w3TJFVA7myeUGQyGt-g_yvpQ",
                "y": "f-E-hYE3TAWKwhVv9pej9NABs9SX9XsNO80x57jFTyU",
                "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
            }
        },
        "authorization_endpoint": "haip:",
        "response_types_supported": ["vp_token"],
        "vp_formats_supported": {
            "jwt_vp_json": {"alg_values_supported": ["ES256"]},
            "jwt_vc_json": {"alg_values_supported": ["ES256"]},
        },
        "request_object_signing_alg_values_supported": ["ES256"],
        "iat": 1687281195,
        "exp": 1687288395,
    },
}


def test_header():
    WalletInstanceAttestationHeader(**WALLET_INSTANCE_ATTESTATION["header"])
    # alg is ES256 (per eIDAS/IT-Wallet spec, OAUTH-ATTESTATION-CLIENT-AUTH)
    # it should fail if alg is not in supported_algorithms
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader.model_validate(
            WALLET_INSTANCE_ATTESTATION["header"],
            context={"supported_algorithms": None},
        )
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader.model_validate(
            WALLET_INSTANCE_ATTESTATION["header"], context={"supported_algorithms": []}
        )
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader.model_validate(
            WALLET_INSTANCE_ATTESTATION["header"],
            context={"supported_algorithms": ["asd"]},
        )

    WalletInstanceAttestationHeader.model_validate(
        WALLET_INSTANCE_ATTESTATION["header"],
        context={"supported_algorithms": ["ES256"]},
    )

    # x5c is REQUIRED per EUDI TS3 (Section 2.2.1.2): verifiers SHALL use the signing cert
    # in x5c to verify the WIA signature against the Trusted List for Wallet Providers.
    # trust_chain is optional.
    WIA_HEADER_WITH_X5C = dict(WALLET_INSTANCE_ATTESTATION["header"])
    WalletInstanceAttestationHeader(**WIA_HEADER_WITH_X5C)

    # WIA without x5c MUST fail (x5c required per EUDI TS3)
    header_no_x5c = {
        k: v for k, v in WALLET_INSTANCE_ATTESTATION["header"].items() if k != "x5c"
    }
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(**header_no_x5c)

    # WIA with x5c=None MUST fail
    header_x5c_none = dict(WALLET_INSTANCE_ATTESTATION["header"])
    header_x5c_none["x5c"] = None
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(**header_x5c_none)

    # kid is required
    WALLET_INSTANCE_ATTESTATION["header"]["kid"] = None
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(**WALLET_INSTANCE_ATTESTATION["header"])
    del WALLET_INSTANCE_ATTESTATION["header"]["kid"]
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(**WALLET_INSTANCE_ATTESTATION["header"])

    # typ must be "oauth-client-attestation+jwt"
    WALLET_INSTANCE_ATTESTATION["header"]["typ"] = "asd"
    with pytest.raises(ValidationError):
        WalletInstanceAttestationHeader(**WALLET_INSTANCE_ATTESTATION["header"])


def test_payload():
    WalletInstanceAttestationPayload(**WALLET_INSTANCE_ATTESTATION["payload"])
    WalletInstanceAttestationPayload.model_validate(
        WALLET_INSTANCE_ATTESTATION["payload"]
    )

    # iss is not HttpUrl
    WALLET_INSTANCE_ATTESTATION["payload"]["iss"] = WALLET_INSTANCE_ATTESTATION[
        "payload"
    ]["iss"][4:]
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION["payload"]
        )
    WALLET_INSTANCE_ATTESTATION["payload"]["iss"] = (
        "http" + WALLET_INSTANCE_ATTESTATION["payload"]["iss"]
    )
    WalletInstanceAttestationPayload.model_validate(
        WALLET_INSTANCE_ATTESTATION["payload"]
    )

    # empty cnf
    cnf = WALLET_INSTANCE_ATTESTATION["payload"]["cnf"]
    WALLET_INSTANCE_ATTESTATION["payload"]["cnf"] = {}
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION["payload"]
        )
    del WALLET_INSTANCE_ATTESTATION["payload"]["cnf"]
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION["payload"]
        )
    WALLET_INSTANCE_ATTESTATION["payload"]["cnf"] = cnf

    # cnf jwk is not a JWK
    WALLET_INSTANCE_ATTESTATION["payload"]["cnf"]["jwk"] = {}
    with pytest.raises(ValidationError):
        WalletInstanceAttestationPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION["payload"]
        )
