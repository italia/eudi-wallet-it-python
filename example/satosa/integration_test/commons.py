import base64
import datetime
import requests
from typing import Any, Literal
from bs4 import BeautifulSoup
from sd_jwt.holder import SDJWTHolder

from pyeudiw.jwk import JWK
from pyeudiw.jwt import DEFAULT_SIG_KTY_MAP, JWEHelper
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.presentation_exchange.schemas.oid4vc_presentation_definition import PresentationDefinition
from pyeudiw.sd_jwt import (
    # _adapt_keys,
    import_ec,
    issue_sd_jwt,
    load_specification_from_yaml_string
)
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.federation.base import (
    EXP,
    ta_ec,
    ta_ec_signed,
    leaf_cred,
    leaf_cred_jwk,
    leaf_cred_jwk_prot,
    leaf_cred_signed,
    leaf_wallet,
    leaf_wallet_jwk,
    leaf_wallet_signed,
    trust_chain_issuer
)

from saml2_sp import IDP_BASEURL
from settings import (
    CONFIG_DB,
    RP_EID,
    its_trust_chain
)

CREDENTIAL_ISSUER_JWK = JWK(leaf_cred_jwk_prot.serialize(private=True))
ISSUER_CONF = {
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
    "issuer": leaf_cred['sub'],
    "default_exp": 1024,
    "key_binding": True
}
ISSUER_PRIVATE_JWK = JWK(leaf_cred_jwk.serialize(private=True))
WALLET_PRIVATE_JWK = JWK(leaf_wallet_jwk.serialize(private=True))
WALLET_PUBLIC_JWK = JWK(leaf_wallet_jwk.serialize())


def setup_test_db_engine() -> DBEngine:
    return DBEngine(CONFIG_DB)


def apply_trust_settings(db_engine_inst: DBEngine) -> DBEngine:
    db_engine_inst.add_trust_anchor(
        entity_id=ta_ec['iss'],
        entity_configuration=ta_ec_signed,
        exp=EXP
    )

    db_engine_inst.add_or_update_trust_attestation(
        entity_id=RP_EID,
        attestation=its_trust_chain,
        exp=datetime.datetime.now().isoformat()
    )

    db_engine_inst.add_or_update_trust_attestation(
        entity_id=leaf_wallet['iss'],
        attestation=leaf_wallet_signed,
        exp=datetime.datetime.now().isoformat()
    )

    db_engine_inst.add_or_update_trust_attestation(
        entity_id=leaf_cred['iss'],
        attestation=leaf_cred_signed,
        exp=datetime.datetime.now().isoformat()
    )
    return db_engine_inst


def create_issuer_test_data() -> dict[Literal["jws"] | Literal["issuance"], str]:
    # create a SD-JWT signed by a trusted credential issuer
    settings = ISSUER_CONF
    settings['issuer'] = leaf_cred['iss']
    settings['default_exp'] = 33
    sd_specification = load_specification_from_yaml_string(
        settings["sd_specification"]
    )

    issued_jwt = issue_sd_jwt(
        sd_specification,
        settings,
        CREDENTIAL_ISSUER_JWK,
        WALLET_PUBLIC_JWK,
        trust_chain=trust_chain_issuer,
        additional_headers={"typ": "vc+sd-jwt"}
    )
    return issued_jwt


def create_holder_test_data(issued_jwt: dict[Literal["jws"] | Literal["issuance"], str], request_nonce: str, verifier_id: str) -> str:
    settings = ISSUER_CONF

    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format="compact",
    )
    sdjwt_at_holder.create_presentation(
        claims_to_disclose={
            'tax_id_code': "TINIT-XXXXXXXXXXXXXXXX",
            'given_name': 'Mario',
            'family_name': 'Rossi'
        },
        nonce=request_nonce,
        aud=verifier_id,
        sign_alg=DEFAULT_SIG_KTY_MAP[WALLET_PRIVATE_JWK.key.kty],
        holder_key=(
            import_ec(
                WALLET_PRIVATE_JWK.key.priv_key,
                kid=WALLET_PRIVATE_JWK.kid
            )
            if settings.get("key_binding", False)
            else None
        )
    )

    vp_token = sdjwt_at_holder.sd_jwt_presentation
    return vp_token


def create_authorize_response(vp_token: str, state: str, nonce: str, response_uri: str) -> str:
    # take relevant information from RP's entity configuration
    client = requests.Session()
    rp_ec_jwt = client.get(
        f'{IDP_BASEURL}/OpenID4VP/.well-known/openid-federation',
        verify=False
    ).content.decode()
    rp_ec = decode_jwt_payload(rp_ec_jwt)

    presentation_definition = rp_ec["metadata"]["wallet_relying_party"]["presentation_definition"]
    PresentationDefinition(**presentation_definition)
    assert response_uri == rp_ec["metadata"]['wallet_relying_party']["response_uris_supported"][0]

    response = {
        "state": state,
        "vp_token": vp_token,
        "presentation_submission": {
            "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
            "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
            "descriptor_map": [
                {
                    "id": "pid-sd-jwt:unique_id+given_name+family_name",
                    "path": "$.vp_token.verified_claims.claims._sd[0]",
                    "format": "vc+sd-jwt"
                }
            ],
            "aud": response_uri
        }
    }
    encrypted_response = JWEHelper(
        # RSA (EC is not fully supported todate)
        JWK(rp_ec["metadata"]['wallet_relying_party']['jwks']['keys'][1])
    ).encrypt(response)
    return encrypted_response


def extract_saml_attributes(saml_response: str) -> set[Any]:
    soup = BeautifulSoup(saml_response, features="lxml")
    form = soup.find("form")
    assert "/saml2" in form["action"]
    input_tag = soup.find("input")
    assert input_tag["name"] == "SAMLResponse"

    lowered = base64.b64decode(input_tag["value"]).lower()
    value = BeautifulSoup(lowered, features="xml")
    attributes = value.find_all("saml:attribute")
    return attributes
