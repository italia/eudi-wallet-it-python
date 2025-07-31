from cryptojwt.jwk.ec import new_ec_key
from pymdoccbor.mdoc.issuer import MdocCborIssuer

from integration_test.initializer.commons import *

NOW = iat_now()
EXP = exp_from_now(5000)

# Define leaf Credential Issuer
ec_crv = "P-256"
ec_alg = "ES256"
#TODO: Use a proper kid as config.metadata_jwks[crv=ec_crv].kid
kid="SQgNjv4yU8sfuafJ2DPWq2tnOlK1JSibd3V5KqYRhOk"
x = "Q46FDkhMjewZIP9qP8ZKZIP-ZEemctvjxeP0l3vWHMI"
y = "IT7lsGxdJewmonk9l1_TAVYx_nixydTtI1Sbn0LkfEA"
duckle_leaf_cred_jwk_prot = new_ec_key(ec_crv, alg=ec_alg, kid=kid, x=x, y=y)
set_credential_issuer_jwk_conf(JWK(duckle_leaf_cred_jwk_prot.serialize(private=True)))

duckle_leaf_cred_jwk = new_ec_key(ec_crv, alg=ec_alg, kid=kid, x=x, y=y)
duckle_leaf_cred = {
    "exp": EXP,
    "iat": NOW,
    "iss": "http://localhost",
    "sub": "http://localhost",
    "jwks": {"keys": []},
    "metadata": {
        "openid_credential_issuer": {"jwks": {"keys": []}},
        "federation_entity": {
            "organization_name": "OpenID Credential Issuer example",
            "homepage_uri": "https://credential-issuer.example.org/home",
            "policy_uri": "https://credential-issuer.example.org/policy",
            "logo_uri": "https://credential-issuer.example.org/static/logo.svg",
            "contacts": ["tech@credential-issuer.example.org"],
        },
    },
    "authority_hints": ["https://intermediate.eidas.example.org"],
}
duckle_leaf_cred["jwks"]["keys"] = [duckle_leaf_cred_jwk.serialize()]
duckle_leaf_cred["metadata"]["openid_credential_issuer"]["jwks"]["keys"] = [
    duckle_leaf_cred_jwk.serialize()
]

DUCKLE_ISSUER_CONF = {
    "sd_specification": """
        !sd unique_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        !sd given_name: "Mario"
        !sd family_name: "Rossi"
        !sd birthdate: "1980-01-10"
        !sd place_of_birth:
            country: "IT"
            locality: "Rome"
        !sd tax_id_code: "TINIT-XXXXXXXXXXXXXXXX"
    """,
    "issuer": duckle_leaf_cred['sub'],
    "default_exp": 1024,
    "key_binding": True
}

set_issuer_conf(DUCKLE_ISSUER_CONF)

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

def create_authorize_response(vp_token: dict, state: str) -> str:
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
