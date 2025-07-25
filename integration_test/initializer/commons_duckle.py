from io import StringIO
from typing import Literal

import requests
from pymdoccbor.mdoc.issuer import MdocCborIssuer

from integration_test.initializer.commons import create_issuer_test_data, create_holder_test_data, \
    create_issuer_test_data_with_user_claims
from pyeudiw.jwk import JWK
from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.sd_jwt.utils.yaml_specification import yaml_load_specification
from pyeudiw.tests.federation.base import leaf_cred
from integration_test.initializer.settings import IDP_BASEURL

ISSUER_CONFIG_FOR_WALLET_ATTESTATION_DATA = {
    "sd_specification": """
        !sd wallet_link: "https://user.example.com/wallet/abc123"
        !sd wallet_name: "Mario’s eID Wallet"
    """,
    "issuer": leaf_cred['sub'],
    "default_exp": 1024,
    "key_binding": True
}

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': b"<\xe5\xbc;\x08\xadF\x1d\xc5\x0czR'T&\xbb\x91\xac\x84\xdc\x9ce\xbf\x0b,\x00\xcb\xdd\xbf\xec\xa2\xa5",
    'KID': b"demo-kid"
}
mdoci = MdocCborIssuer(
    private_key=PKEY,
    alg="ES256",
)

def create_verifiable_presentations(request_nonce: str, request_aud: str) -> dict:
    return  {
        "personal id data": create_holder_test_data(create_issuer_test_data(),request_nonce,request_aud),
        "wallet attestation": create_holder_test_data(create_wallet_attestation_data(),request_nonce,request_aud),
        #"wallet attestation": create_mso_mdoc(
        #   {
        #        "eu.europa.ec.eudiw.pid.1": {
        #            "wallet_link": "https://user.example.com/wallet/abc123",
        #            "wallet_name": "Mario’s eID Wallet"
        #        }
        #    }
        #)
    }

def create_wallet_attestation_data() -> dict[Literal["jws"] | Literal["issuance"], str]:
    settings = ISSUER_CONFIG_FOR_WALLET_ATTESTATION_DATA
    settings["default_exp"] = 33
    user_claims = yaml_load_specification(StringIO(settings["sd_specification"]))
    return create_issuer_test_data_with_user_claims(user_claims)

def create_authorize_response_duckle(state: str, vp_token: dict):
    # Extract public key from RP's entity configuration
    client = requests.Session()
    rp_ec_jwt = client.get(
        f"{IDP_BASEURL}/OpenID4VP/.well-known/openid-federation",
        verify=False
    ).content.decode()
    rp_ec = decode_jwt_payload(rp_ec_jwt)

    encryption_key = rp_ec["metadata"]["openid_credential_verifier"]["jwks"]["keys"][1]

    response = {
        "state": state,
        "vp_token": vp_token
    }
    encrypted_response = JWEHelper(
        # RSA (EC is not fully supported to date)
        JWK(encryption_key).as_dict()
    ).encrypt(response)
    return encrypted_response


def create_mso_mdoc(subject_claims: dict) -> str:
    mdoci.new(
        doctype="eu.europa.ec.eudiw.pid.1",
        data=subject_claims,
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        }
    )
    return mdoci.dumps().decode()
