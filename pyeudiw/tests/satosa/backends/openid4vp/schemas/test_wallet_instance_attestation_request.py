import pytest
from pydantic import ValidationError

from pyeudiw.satosa.backends.openid4vp.schemas.wallet_instance_attestation_request import (
    WalletInstanceAttestationRequestHeader,
    WalletInstanceAttestationRequestPayload,
)

WALLET_INSTANCE_ATTESTATION_REQUEST = {
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
                    "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MD"
                    "EyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0u"
                    "l+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR"
                    "8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDa"
                    "Ho4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQ"
                    "ADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xh"
                    "klAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYaw"
                    "xYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
                ],
                "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6R"
                "ZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfV"
                "rbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
                "e": "AQAB",
                "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
                "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
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
        context={"supported_algorithms": ["RS256", "ES256"]},
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
    WALLET_INSTANCE_ATTESTATION_REQUEST["payload"]["type"] = "wrong"
    with pytest.raises(ValidationError):
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

