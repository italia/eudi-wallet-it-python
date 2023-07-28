import hashlib

import pytest

from pyeudiw.oauth2.dpop import DPoPIssuer, DPoPVerifier
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header
from pyeudiw.tools.utils import iat_now


PRIVATE_JWK = JWK()
PUBLIC_JWK = PRIVATE_JWK.public_key


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
        "jwk": PUBLIC_JWK
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


@pytest.fixture
def wia_jws(jwshelper):
    wia = jwshelper.sign(
        WALLET_INSTANCE_ATTESTATION,
        protected={'trust_chain': [], 'x5c': []}
    )
    return wia


def test_create_validate_dpop_http_headers(wia_jws, private_jwk=PRIVATE_JWK):
    # create
    header = unpad_jwt_header(wia_jws)
    assert header
    assert isinstance(header["trust_chain"], list)
    assert isinstance(header["x5c"], list)
    assert header["alg"]
    assert header["kid"]

    new_dpop = DPoPIssuer(
        htu='https://example.org/redirect',
        token=wia_jws,
        private_jwk=private_jwk
    )
    proof = new_dpop.proof
    assert proof

    header = unpad_jwt_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"]
    assert "mac" not in str(header["alg"]).lower()
    assert "d" not in header["jwk"]

    payload = unpad_jwt_payload(proof)
    assert payload["ath"] == hashlib.sha256(wia_jws.encode()).hexdigest()
    assert payload["htm"] in ["GET", "POST", "get", "post"]
    assert payload["htu"] == "https://example.org/redirect"
    assert payload["jti"]
    assert payload["iat"]

    # verify
    dpop = DPoPVerifier(
        public_jwk=PUBLIC_JWK,
        http_header_authz=f"DPoP {wia_jws}",
        http_header_dpop=proof
    )
    assert dpop.is_valid

    other_jwk = JWK(key_type="RSA").public_key
    dpop = DPoPVerifier(
        public_jwk=other_jwk,
        http_header_authz=f"DPoP {wia_jws}",
        http_header_dpop=proof
    )
    assert dpop.is_valid is False

    with pytest.raises(ValueError):
        dpop = DPoPVerifier(
            public_jwk=PUBLIC_JWK,
            http_header_authz=f"DPoP {wia_jws}",
            http_header_dpop="aaa"
        )
        assert dpop.is_valid is False

    with pytest.raises(ValueError):
        dpop = DPoPVerifier(
            public_jwk=PUBLIC_JWK,
            http_header_authz=f"DPoP {wia_jws}",
            http_header_dpop="aaa" + proof[3:]
        )
        assert dpop.is_valid is False
