import base64
import datetime
import json
import os
import time
import uuid
from copy import deepcopy
from io import StringIO
from typing import Any, Literal

import requests
import yaml
from bs4 import BeautifulSoup
from jose import jwt

from pyeudiw.jwk import JWK
from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.jwt.jws_helper import DEFAULT_SIG_KTY_MAP, JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.sd_jwt.holder import SDJWTHolder
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.utils.yaml_specification import _yaml_load_specification
from pyeudiw.storage.base_storage import TrustType
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.federation.base import (
    EXP,
    ta_ec,
    ta_ec_signed,
    leaf_cred,
    leaf_cred_jwk_prot,
    leaf_cred_signed,
    leaf_wallet,
    leaf_wallet_jwk,
    leaf_wallet_signed,
)
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.trust.model.trust_source import TrustSourceData
from .saml2_sp import saml2_request
from .settings import (
    IDP_BASEURL,
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
CREDENTIAL_ISSUER_TRUST_SOURCE_Dict = {
    "entity_id": ISSUER_CONF["issuer"],
    "policies": {},
    "metadata": {},
    "revoked": False,
    "direct_trust_sd_jwt_vc": {
        "attribute_name": "jwks",
        "expiration_date": exp_from_now(1024),
        "jwks": [CREDENTIAL_ISSUER_JWK.as_dict()],
        "trust_handler_name": "DirectTrustSdJwtVc",
    },
}
CREDENTIAL_ISSUER_TRUST_SOURCE = TrustSourceData(**CREDENTIAL_ISSUER_TRUST_SOURCE_Dict)
WALLET_PRIVATE_JWK = JWK(leaf_wallet_jwk.serialize(private=True))
WALLET_PUBLIC_JWK = JWK(leaf_wallet_jwk.serialize())


def setup_test_db_engine() -> DBEngine:
    return DBEngine(CONFIG_DB)


def apply_trust_settings(db_engine_inst: DBEngine) -> DBEngine:
    db_engine_inst.add_trust_anchor(
        entity_id=ta_ec["iss"],
        entity_configuration=ta_ec_signed,
        exp=EXP
    )

    db_engine_inst.add_or_update_trust_attestation(
        entity_id=RP_EID,
        attestation=its_trust_chain,
        exp=datetime.datetime.now().isoformat()
    )

    db_engine_inst.add_or_update_trust_attestation(
        entity_id=leaf_wallet["iss"],
        attestation=leaf_wallet_signed,
        exp=datetime.datetime.now().isoformat()
    )

    db_engine_inst.add_or_update_trust_attestation(
        entity_id=leaf_cred["iss"],
        attestation=leaf_cred_signed,
        exp=datetime.datetime.now().isoformat(),
        trust_type=TrustType.FEDERATION
    )

    settings = ISSUER_CONF
    db_engine_inst.add_or_update_trust_attestation(
        entity_id=settings["issuer"],
        trust_type=TrustType.DIRECT_TRUST_SD_JWT_VC,
        jwks=[leaf_cred_jwk_prot.serialize()]
    )

    db_engine_inst.add_trust_source(
        trust_source=CREDENTIAL_ISSUER_TRUST_SOURCE_Dict
    )
    return db_engine_inst


def create_saml_auth_request() -> str:
    auth_req_url = f"{saml2_request['headers'][0][1]}&idp_hinting=wallet"
    return auth_req_url


def create_issuer_test_data() -> dict[Literal["jws"] | Literal["issuance"], str]:
    # create a SD-JWT signed by a trusted credential issuer
    extra_header_parameters={
        "typ": "dc+sd-jwt",
        "kid": CREDENTIAL_ISSUER_JWK.kid
    }
    return _create_generic_issuer_test_data("compact", extra_header_parameters)

def create_issuer_test_data_duckle() -> dict[Literal["jws"] | Literal["issuance"], str]:
    extra_header_parameters={
        "typ": "dcql",
        "kid": CREDENTIAL_ISSUER_JWK.kid
    }
    return _create_generic_issuer_test_data("json", extra_header_parameters)

def _create_generic_issuer_test_data(serialization_format: str, extra_header_parameters: dict) -> dict[Literal["jws"] | Literal["issuance"], str]:
    # create a SD-JWT signed by a trusted credential issuer
    settings = ISSUER_CONF
    settings["default_exp"] = 33

    user_claims = _yaml_load_specification(StringIO(settings["sd_specification"]))
    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": exp_from_now(settings["default_exp"])  # in seconds
    }
    user_claims.update(claims)
    public_holder_key = deepcopy(WALLET_PUBLIC_JWK.as_dict())
    public_holder_key.pop("kid", None)  # condifmration key can be expressed without a kid
    issued_jwt = SDJWTIssuer(
        issuer_keys=CREDENTIAL_ISSUER_JWK.as_dict(),
        holder_key=public_holder_key,
        extra_header_parameters = extra_header_parameters,
        serialization_format=serialization_format,
        user_claims=user_claims,
        add_decoy_claims=claims.get("add_decoy_claims", True)
    )

    return {"jws": issued_jwt.serialized_sd_jwt, "issuance": issued_jwt.sd_jwt_issuance}

def create_holder_test_data(issued_jwt: dict[Literal["jws"] | Literal["issuance"], str], request_nonce: str, request_aud: str) -> str:
    claims_to_disclose={
        "tax_id_code": True,
        "given_name": True,
        "family_name": True
    }
    serialization_format="compact"
    return _create_generic_holder_test_data(issued_jwt, request_nonce, request_aud, serialization_format, claims_to_disclose)

def create_holder_test_data_with_duckle(
        request_nonce: str,
        request_aud: str,
) -> str:
    now = int(time.time())

    payload = {
        "iss": "redirect_uri:https://client.example.org/cb",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 600,  # valido per 10 minuti
        "nonce": request_nonce,
        "sub": RP_EID,
        "aud": request_aud,
        "dcql_query": {
            "credentials": [
                {
                    "credential_format": 'mso_mdoc',
                    "doctype": 'org.iso.18013.5.1.mDL',
                    "namespaces": {
                        'org.iso.18013.5.1': {
                            "given_name": 'Mario',
                            "family_name": 'Rossi',
                        },
                    },
                },
                {
                    "credential_format": 'mso_mdoc',
                    "doctype": 'org.iso.18013.5.1.mDL',
                    "namespaces": {
                        'org.iso.18013.5.1': {
                            "resident_country": 'Italy',
                            "resident_address": 'Via Roma 1',
                            "non_disclosed": 'secret',
                        }
                    }
                }
            ]
        }
    }
    algorithm = "ES256"
    key = filter_keys_by_algorithm(algorithm)
    headers = {
        "alg": algorithm,
        "typ": "dcql",
        "kid": key.get("kid")
    }
    token = jwt.encode(
        claims=payload,
        key=key,
        algorithm=algorithm,
        headers=headers
    )

    return token

def _create_generic_holder_test_data(
        issued_jwt: dict[Literal["jws"] | Literal["issuance"], str],
        request_nonce: str,
        request_aud: str,
        serialization_format: str,
        claims_to_disclose: dict[str, bool]
) -> str:
    settings = ISSUER_CONF

    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format=serialization_format,
    )

    holder_private_key: dict | None = WALLET_PRIVATE_JWK.as_dict() if settings.get("key_binding", False) else None
    sdjwt_at_holder.create_presentation(
        claims_to_disclose = claims_to_disclose,
        nonce=request_nonce,
        aud=request_aud,
        sign_alg=DEFAULT_SIG_KTY_MAP[WALLET_PRIVATE_JWK.key.kty],
        holder_key=holder_private_key
    )
    vp_token = sdjwt_at_holder.sd_jwt_presentation
    return vp_token

def create_authorize_response_duckle(vp_token: str, state: str, response_uri: str) -> str:
    # Extract public key from RP's entity configuration
    client = requests.Session()
    rp_ec_jwt = client.get(
        f"{IDP_BASEURL}/OpenID4VP/.well-known/openid-federation",
        verify=False
    ).content.decode()
    rp_ec = decode_jwt_payload(rp_ec_jwt)

    #  assert response_uri == rp_ec["metadata"]["openid_credential_verifier"]["response_uris"][0]
    encryption_key = rp_ec["metadata"]["openid_credential_verifier"]["jwks"]["keys"][1]

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
                    "format": "jwt_vc_json"
                }
            ],
            "aud": response_uri
        }
    }
    encrypted_response = JWEHelper(
        # RSA (EC is not fully supported to date)
        JWK(encryption_key).as_dict()
    ).encrypt(response)
    return encrypted_response

def create_authorize_response(vp_token: str, state: str, response_uri: str) -> str:
    # Extract public key from RP's entity configuration
    client = requests.Session()
    rp_ec_jwt = client.get(
        f"{IDP_BASEURL}/OpenID4VP/.well-known/openid-federation",
        verify=False
    ).content.decode()
    rp_ec = decode_jwt_payload(rp_ec_jwt)

    #  assert response_uri == rp_ec["metadata"]["openid_credential_verifier"]["response_uris"][0]
    encryption_key = rp_ec["metadata"]["openid_credential_verifier"]["jwks"]["keys"][1]

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
                    "format": "dc+sd-jwt"
                }
            ],
            "aud": response_uri
        }
    }
    encrypted_response = JWEHelper(
        # RSA (EC is not fully supported to date)
        JWK(encryption_key).as_dict()
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


def verify_request_object_jwt(ro: str, client: requests.Session):
    well_known_endpoint = f"{IDP_BASEURL}/.well-known/jar-issuer/OpenID4VP"
    metadata_raw = client.get(well_known_endpoint, verify=False).content.decode()
    metadata = json.loads(metadata_raw)
    verifier = JWSHelper(metadata["jwks"]["keys"])
    verifier.verify(ro)

class IgnoreUnknownTagsLoader(yaml.SafeLoader):
    pass

def ignore_unknown(loader, tag_suffix, node):
    return loader.construct_scalar(node)

IgnoreUnknownTagsLoader.add_multi_constructor('', ignore_unknown)

def filter_keys_by_algorithm(algorithm: str) -> dict:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    yaml_path = os.path.normpath(os.path.join(current_dir, "..", "pyeudiw_backend.yaml"))

    with open(yaml_path, "r", encoding="utf-8") as f:
        config = yaml.load(f, Loader=IgnoreUnknownTagsLoader)

    metadata_jwks = config.get("config", {}).get("metadata_jwks", [])
    for key in metadata_jwks:
        if key.get("alg") == algorithm:
            return key