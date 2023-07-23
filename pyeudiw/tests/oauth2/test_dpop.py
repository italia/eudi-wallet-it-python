import pytest

from pyeudiw.jwk import JWK
from pyeudiw.tools.jwt import JWSHelper
from pyeudiw.tools.utils import iat_now


WALLET_INSTANCE_ATTESTATION = {
    "iss": "https://wallet-provider.example.org",
    "sub": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
    "type": "WalletInstanceAttestation",
    "policy_uri": "https://wallet-provider.example.org/privacy_policy",
    "tos_uri": "https://wallet-provider.example.org/info_policy",
    "logo_uri": "https://wallet-provider.example.org/logo.svg",
    "asc": "https://wallet-provider.example.org/LoA/basic",
    "cnf":
    {
        "jwk":
        {
            "crv": "P-256",
            "kty": "EC",
            "x": "4HNptI-xr2pjyRJKGMnz4WmdnQD_uJSq4R95Nj98b44",
            "y": "LIZnSB39vFJhYgS3k7jXE4r3-CoGFQwZtPBIRqpNlrg",
            "kid": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c"
        }
    },
    "authorization_endpoint": "eudiw:",
    "response_types_supported": [
        "vp_token"
    ],
    "vp_formats_supported": {
        "jwt_vp_json": {
            "alg_values_supported": ["ES256"]
        },
        "jwt_vc_json": {
            "alg_values_supported": ["ES256"]
        }
    },
    "request_object_signing_alg_values_supported": [
        "ES256"
    ],
    "presentation_definition_uri_supported": False,
    "iat": iat_now(),
    "exp": iat_now() + 1024
}


@pytest.fixture
def private_jwk():
    return JWK()


@pytest.fixture
def jwshelper(private_jwk):
    return JWSHelper(private_jwk)


def test_create(jwshelper):
    jwshelper.sign(WALLET_INSTANCE_ATTESTATION)


def test_validate():
    pass
