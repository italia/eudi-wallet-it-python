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
    assert header["trust_chain"] == []
    assert header["x5c"] == []
    assert header["alg"]
    assert header["kid"]
    
    payload = unpad_jwt_payload(wia_jws)
    assert payload
    assert payload["iss"] == WALLET_INSTANCE_ATTESTATION["iss"]
    assert payload["sub"] == WALLET_INSTANCE_ATTESTATION["sub"]
    assert payload["type"] == WALLET_INSTANCE_ATTESTATION["type"]
    assert payload["policy_uri"] == WALLET_INSTANCE_ATTESTATION["policy_uri"]
    assert payload["tos_uri"] == WALLET_INSTANCE_ATTESTATION["tos_uri"]
    assert payload["logo_uri"] == WALLET_INSTANCE_ATTESTATION["logo_uri"]
    assert payload["asc"] == WALLET_INSTANCE_ATTESTATION["asc"]
    assert payload["cnf"]
    assert payload["cnf"]["jwk"]
    assert payload["cnf"]["jwk"]["kty"]
    assert payload["cnf"]["jwk"]["crv"]
    assert payload["cnf"]["jwk"]["kid"]
    assert payload["cnf"]["jwk"]["x"]
    assert payload["cnf"]["jwk"]["y"]
    assert payload["authorization_endpoint"] == WALLET_INSTANCE_ATTESTATION["authorization_endpoint"]
    assert payload["response_types_supported"] == WALLET_INSTANCE_ATTESTATION["response_types_supported"]
    assert payload["vp_formats_supported"] == WALLET_INSTANCE_ATTESTATION["vp_formats_supported"]
   
    new_dpop = DPoPIssuer(
        htu='https://example.org/redirect',
        token=wia_jws,
        private_jwk=private_jwk
    )
    proof = new_dpop.proof
    assert proof

    # verify
    dpop = DPoPVerifier(
        public_jwk=payload['cnf']['jwk'],
        http_header_authz=f"DPoP {wia_jws}",
        http_header_dpop=proof
    )

    assert dpop.is_valid
    
    
    # Notes:
    # `is_valid` should return False in case the underlying checks fail for some reason.
    # In the following cases, the function is tested against invalid inputs
    
    # Error case: wrong JWK
    
    # TODO fix code causing:
    # FAILED Exception: kid error

    # jwk = JWK(key_type="RSA").public_key
    # dpop = DPoPVerifier(
    #     public_jwk=jwk,
    #     http_header_authz=f"DPoP {wia_jws}",
    #     http_header_dpop=proof
    # )
    # assert dpop.is_valid == False
    
    
    # Error case: invalid proof
    
    # TODO fix code causing:
    # FAILED UnicodeDecodeError: 'utf-8' codec can't decode byte (invalid start byte)
    
    # dpop = DPoPVerifier(
    #     public_jwk=payload['cnf']['jwk'],
    #     http_header_authz=f"DPoP {wia_jws}",
    #     http_header_dpop="aaa" + proof[3:]
    # )
    # assert dpop.is_valid == False
    