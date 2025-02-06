import base64
import hashlib

import pytest
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.rsa import new_rsa_key

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop import DPoPIssuer, DPoPVerifier
from pyeudiw.tools.utils import iat_now

PRIVATE_JWK_EC = new_ec_key("P-256")
PRIVATE_JWK = PRIVATE_JWK_EC.serialize(private=True)
PUBLIC_JWK = PRIVATE_JWK_EC.serialize()


WALLET_INSTANCE_ATTESTATION = {
    "iss": "https://wallet-provider.example.org",
    "sub": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
    "type": "WalletInstanceAttestation",
    "policy_uri": "https://wallet-provider.example.org/privacy_policy",
    "tos_uri": "https://wallet-provider.example.org/info_policy",
    "logo_uri": "https://wallet-provider.example.org/logo.svg",
    "aal": "https://wallet-provider.example.org/LoA/basic",
    "cnf": {"jwk": PUBLIC_JWK},
    "authorization_endpoint": "haip:",
    "response_types_supported": ["vp_token"],
    "vp_formats_supported": {
        "jwt_vp_json": {"alg_values_supported": ["ES256"]},
        "jwt_vc_json": {"alg_values_supported": ["ES256"]},
    },
    "request_object_signing_alg_values_supported": ["ES256"],
    "presentation_definition_uri_supported": False,
    "iat": iat_now(),
    "exp": iat_now() + 1024,
}


@pytest.fixture
def private_jwk():
    return new_ec_key("P-256")


@pytest.fixture
def jwshelper(private_jwk):
    return JWSHelper(private_jwk)


@pytest.fixture
def wia_jws(jwshelper):
    wia = jwshelper.sign(
        WALLET_INSTANCE_ATTESTATION, protected={"trust_chain": [], "x5c": []}
    )
    return wia


def test_create_validate_dpop_http_headers(wia_jws, private_jwk=PRIVATE_JWK_EC):
    # create
    header = decode_jwt_header(wia_jws)
    assert header
    assert isinstance(header["trust_chain"], list)
    assert isinstance(header["x5c"], list)
    assert header["alg"]

    new_dpop = DPoPIssuer(
        htu="https://example.org/redirect", token=wia_jws, private_jwk=private_jwk
    )
    proof = new_dpop.proof
    assert proof

    header = decode_jwt_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"]
    assert "mac" not in str(header["alg"]).lower()
    assert "d" not in header["jwk"]

    payload = decode_jwt_payload(proof)
    assert (
        payload["ath"]
        == base64.urlsafe_b64encode(hashlib.sha256(wia_jws.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert payload["htm"] in ["GET", "POST", "get", "post"]
    assert payload["htu"] == "https://example.org/redirect"
    assert payload["jti"]
    assert payload["iat"]

    # verify
    dpop = DPoPVerifier(
        public_jwk=PUBLIC_JWK,
        http_header_authz=f"DPoP {wia_jws}",
        http_header_dpop=proof,
    )
    assert dpop.is_valid

    other_jwk = new_rsa_key().serialize()
    dpop = DPoPVerifier(
        public_jwk=other_jwk,
        http_header_authz=f"DPoP {wia_jws}",
        http_header_dpop=proof,
    )
    with pytest.raises(Exception):
        dpop.validate()

    with pytest.raises(ValueError):
        dpop = DPoPVerifier(
            public_jwk=PUBLIC_JWK,
            http_header_authz=f"DPoP {wia_jws}",
            http_header_dpop="aaa",
        )
        assert dpop.is_valid is False

    with pytest.raises(ValueError):
        dpop = DPoPVerifier(
            public_jwk=PUBLIC_JWK,
            http_header_authz=f"DPoP {wia_jws}",
            http_header_dpop="aaa" + proof[3:],
        )
