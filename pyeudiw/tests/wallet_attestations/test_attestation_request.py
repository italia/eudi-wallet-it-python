import pytest
from pydantic import ValidationError

from pyeudiw.wallet_attestations import (
    WalletInstanceAttestationRequestHeader,
    WalletInstanceAttestationRequestPayload,
)

WALLET_INSTANCE_ATTESTATION_REQUEST = {
    "header": {
        "alg": "ES256",
        "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
        "typ": "attestations-request+jwt",
    },
    "payload": {
        "iss": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
        "aud": "https://wallet-provider.example.org",
        "jti": "6ec69324-60a8-4e5b-a697-a766d85790ea",
        "type": "WalletInstanceAttestationRequest",
        "nonce": ".....",
        # IT-Wallet (eidas-it-wallet-docs) wallet-attestation-issuance.rst Steps 9–22:
        # hardware_signature: proof of possession of Cryptographic Hardware Keys (WP_140d)
        # integrity_assertion: from Device Integrity Service, signed by OEM (WP_140e)
        # attested_key: key_attestation (Android) or integrity_assertion (iOS) signed with credential key (Steps 13–20)
        # hardware_key_tag: id of Wallet Instance hardware keypair (Table: Wallet App and Wallet Unit Attestation Request Body)
        "hardware_signature": "base64encoded_hw_sig",
        "integrity_assertion": "base64encoded_integrity",
        "attested_key": "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IngiLCJ5IjoieSJ9",
        "hardware_key_tag": "hw_key_tag_1",
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
        "iat": 1686645115,
        "exp": 1686652315,
    },
}


def test_header():
    WalletInstanceAttestationRequestHeader(
        **WALLET_INSTANCE_ATTESTATION_REQUEST["header"]
    )
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestHeader.model_validate(
            WALLET_INSTANCE_ATTESTATION_REQUEST["header"],
            context={"supported_algorithms": ["RS128", "ES128"]},
        )
    WalletInstanceAttestationRequestHeader.model_validate(
        WALLET_INSTANCE_ATTESTATION_REQUEST["header"],
        context={"supported_algorithms": ["ES256", "ES384"]},
    )
    WALLET_INSTANCE_ATTESTATION_REQUEST["header"]["typ"] = "wrong"
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestHeader(
            **WALLET_INSTANCE_ATTESTATION_REQUEST["header"]
        )


def test_payload():
    WalletInstanceAttestationRequestPayload(
        **WALLET_INSTANCE_ATTESTATION_REQUEST["payload"]
    )

    WALLET_INSTANCE_ATTESTATION_REQUEST["payload"]["cnf"] = {
        "wrong_name_jwk": WALLET_INSTANCE_ATTESTATION_REQUEST["payload"]["cnf"]["jwk"]
    }
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestPayload.model_validate(
            WALLET_INSTANCE_ATTESTATION_REQUEST["payload"]
        )


def test_wir():
    wir_dict = {
        "header": {
            "alg": "ES256",
            "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
            "typ": "attestations-request+jwt",
        },
        "payload": {
            "iss": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
            "aud": "https://wallet-provider.example.org",
            "jti": "6ec69324-60a8-4e5b-a697-a766d85790ea",
            "type": "WalletInstanceAttestationRequest",
            "nonce": ".....",
            # See IT-Wallet wallet-attestation-issuance.rst (Steps 9–22, Table of Attestation Request Body)
            "hardware_signature": "base64encoded_hw_sig",
            "integrity_assertion": "base64encoded_integrity",
            "attested_key": "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IngiLCJ5IjoieSJ9",
            "hardware_key_tag": "hw_key_tag_1",
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
            "iat": 1686645115,
            "exp": 1686652315,
        },
    }

    WalletInstanceAttestationRequestHeader(**wir_dict["header"])
    WalletInstanceAttestationRequestPayload(**wir_dict["payload"])

    WalletInstanceAttestationRequestHeader.model_validate(
        wir_dict["header"], context={"supported_algorithms": ["ES256"]}
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
            wir_dict["header"], context={"supported_algorithms": ["RS256"]}
        )

    wir_dict["payload"]["cnf"] = {"wrong_name_jwk": wir_dict["payload"]["cnf"]["jwk"]}
    with pytest.raises(ValidationError):
        WalletInstanceAttestationRequestPayload.model_validate(
            wir_dict["payload"], context={"supported_algorithms": ["ES256"]}
        )
    wir_dict["payload"]["cnf"] = {"jwk": wir_dict["payload"]["cnf"]["wrong_name_jwk"]}
