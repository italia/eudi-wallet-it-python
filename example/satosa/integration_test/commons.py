import base64
import datetime
import json
import urllib.parse
from copy import deepcopy
from io import StringIO
from typing import Any, Literal

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import Playwright, Page

from pyeudiw.jwk import JWK
from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.jwt.jws_helper import DEFAULT_SIG_KTY_MAP, JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.sd_jwt.holder import SDJWTHolder
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.utils.yaml_specification import yaml_load_specification
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
    settings = ISSUER_CONF
    settings["default_exp"] = 33
    user_claims = yaml_load_specification(StringIO(settings["sd_specification"]))
    return create_issuer_test_data_with_user_claims(user_claims)

def create_issuer_test_data_with_user_claims(user_claims:dict) -> dict[Literal["jws"] | Literal["issuance"], str]:
    # create a SD-JWT signed by a trusted credential issuer
    settings = ISSUER_CONF
    settings["default_exp"] = 33
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
        extra_header_parameters={
            "typ": "dc+sd-jwt",
            "kid": CREDENTIAL_ISSUER_JWK.kid
        },
        user_claims=user_claims,
        add_decoy_claims=claims.get("add_decoy_claims", True)
    )

    return {"jws": issued_jwt.serialized_sd_jwt, "issuance": issued_jwt.sd_jwt_issuance}


def create_holder_test_data(issued_jwt: dict[Literal["jws"] | Literal["issuance"], str], request_nonce: str, request_aud: str) -> str:
    settings = ISSUER_CONF

    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format="compact",
    )

    holder_private_key: dict | None = WALLET_PRIVATE_JWK.as_dict() if settings.get("key_binding", False) else None
    sdjwt_at_holder.create_presentation(
        claims_to_disclose={
            "tax_id_code": True,
            "given_name": True,
            "family_name": True
        },
        nonce=request_nonce,
        aud=request_aud,
        sign_alg=DEFAULT_SIG_KTY_MAP[WALLET_PRIVATE_JWK.key.kty],
        holder_key=holder_private_key
    )
    vp_token = sdjwt_at_holder.sd_jwt_presentation
    return vp_token


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
from pyeudiw.tools.utils import exp_from_now, iat_now

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
        !sd vct: "urn:eu.europa.ec.eudi:por:1"
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

STATUS_ENDPOINT_URI_JS = "statusEndpoint()+'?id='+sessionIdentifier()"  # javascript functions that yield the status URI; defined in qrcode.html


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
    settings = ISSUER_CONF
    settings["default_exp"] = 33
    user_claims = yaml_load_specification(StringIO(settings["sd_specification"]))
    return create_issuer_test_data_with_user_claims(user_claims)

def create_issuer_test_data_with_user_claims(user_claims:dict) -> dict[Literal["jws"] | Literal["issuance"], str]:
    # create a SD-JWT signed by a trusted credential issuer
    settings = ISSUER_CONF
    settings["default_exp"] = 33
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
        extra_header_parameters={
            "typ": "dc+sd-jwt",
            "kid": CREDENTIAL_ISSUER_JWK.kid
        },
        user_claims=user_claims,
        add_decoy_claims=claims.get("add_decoy_claims", True)
    )

    return {"jws": issued_jwt.serialized_sd_jwt, "issuance": issued_jwt.sd_jwt_issuance}


def create_holder_test_data(issued_jwt: dict[Literal["jws"] | Literal["issuance"], str], request_nonce: str, request_aud: str) -> str:
    settings = ISSUER_CONF

    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format="compact",
    )

    holder_private_key: dict | None = WALLET_PRIVATE_JWK.as_dict() if settings.get("key_binding", False) else None
    sdjwt_at_holder.create_presentation(
        claims_to_disclose={
            "tax_id_code": True,
            "given_name": True,
            "family_name": True
        },
        nonce=request_nonce,
        aud=request_aud,
        sign_alg=DEFAULT_SIG_KTY_MAP[WALLET_PRIVATE_JWK.key.kty],
        holder_key=holder_private_key
    )
    vp_token = sdjwt_at_holder.sd_jwt_presentation
    return vp_token


def create_authorize_response(vp_token: str, state: str, response_uri: str) -> str:
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
        "vp_token": vp_token,
        "presentation_submission": {
            "definition_id": "global-presentation-definition-id ",
            "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
            "descriptor_map": [
                {
                    "id": "another-input-specific-id",
                    "path": "$[0]",
                    "format": "dc+sd-jwt"
                },
            ],
            "aud": response_uri
        }
    }
    encrypted_response = JWEHelper(
        JWK(encryption_key).as_dict()
    ).encrypt(response)
    return encrypted_response


def create_authorize_error_response_user_denies(state: str) -> dict:
    return {
        "error": "access_denied",
        "error_description": "The End-User did not give consent to share the requested Credentials with the Verifier",
        "state": state
    }


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


def verify_status_login_page(login_page: Page, expected_code: int):
    """
    verify_status_login_page invokes the status endpoind though the javascript
    method that pools the very same endpoint.
    """
    current_status = login_page.evaluate(
        f"fetch({STATUS_ENDPOINT_URI_JS}).then(resp => resp.status)"
    )
    assert expected_code == current_status


def extract_request_uri_login_page(page_content: str) -> str:
    """
    extract_request_uri_login_page parses the QR code in the login page
    and returns the request_uri field embedded in the QR code value.
    """
    bs = BeautifulSoup(page_content, features="html.parser")
    # Request URI is extracted by parsing the QR code in the response page
    qrcode_element = list(bs.find(id="content-qrcode-payload").children)[1]
    qrcode_text = qrcode_element.get("contents")
    request_uri = urllib.parse.parse_qs(qrcode_text)["request_uri"][0]
    return request_uri


def extract_content_title_login_page(page_content: str) -> str:
    bs = BeautifulSoup(page_content, features="html.parser")
    content_title_element = list(bs.find(id="content-title").children)[0]
    return content_title_element


def get_new_browser_page(playwright: Playwright) -> Page:
    """
    Returns a browser page that live in a browser instance that is fresh and
    does not share cookies and cache with other browser instances
    """
    webkit = playwright.webkit
    rp_browser = webkit.launch(timeout=0)
    rp_context = rp_browser.new_context(
        ignore_https_errors=True,  # required as otherwise self-signed certificates are not accepted,
        java_script_enabled=True,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36"
    )
    return rp_context.new_page()