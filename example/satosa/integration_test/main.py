import json
import requests
import urllib
import datetime
import base64
from bs4 import BeautifulSoup

from pyeudiw.jwt import DEFAULT_SIG_KTY_MAP
from pyeudiw.presentation_exchange.schemas.oid4vc_presentation_definition import PresentationDefinition
from pyeudiw.tests.federation.base import (
    EXP,
    leaf_cred,
    leaf_cred_jwk,
    leaf_wallet_jwk,
    leaf_wallet,
    leaf_wallet_signed,
    trust_chain_issuer,
    ta_ec,
    ta_ec_signed,
    leaf_cred_signed, leaf_cred_jwk_prot
)

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper, JWEHelper
from pyeudiw.sd_jwt import (
    load_specification_from_yaml_string,
    issue_sd_jwt,
    _adapt_keys,
    import_ec
)
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.jwt.utils import decode_jwt_payload

from saml2_sp import saml2_request, IDP_BASEURL
from sd_jwt.holder import SDJWTHolder

from settings import (
    CONFIG_DB,
    RP_EID,
    its_trust_chain
)

TIMEOUT_S = 4

# put a trust attestation related itself into the storage
# this then is used as trust_chain header paramenter in the signed
# request object
db_engine_inst = DBEngine(CONFIG_DB)

# STORAGE ####
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

req_url = f"{saml2_request['headers'][0][1]}&idp_hinting=wallet"
headers_mobile = {
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B137 Safari/601.1'
}
request_uri = ''

# initialize the user-agent
http_user_agent = requests.Session()

try:
    authn_response = http_user_agent.get(
        url=req_url,
        verify=False,
        headers=headers_mobile,
        timeout=TIMEOUT_S
    )
except requests.exceptions.InvalidSchema as e:
    request_uri = urllib.parse.unquote_plus(
        e.args[0].split("request_uri="
                        )[1][:-1]
    )

WALLET_PRIVATE_JWK = JWK(leaf_wallet_jwk.serialize(private=True))
WALLET_PUBLIC_JWK = JWK(leaf_wallet_jwk.serialize())
jwshelper = JWSHelper(WALLET_PRIVATE_JWK)

sign_request_obj = http_user_agent.get(
    request_uri,
    verify=False,
    timeout=TIMEOUT_S)
print(sign_request_obj.text)

response_uri = decode_jwt_payload(sign_request_obj.text)[
    'response_uri']

# create a SD-JWT signed by a trusted credential issuer
issuer_jwk = leaf_cred_jwk

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
settings = ISSUER_CONF
settings['issuer'] = leaf_cred['iss']
settings['default_exp'] = 33

sd_specification = load_specification_from_yaml_string(
    settings["sd_specification"]
)

ISSUER_PRIVATE_JWK = JWK(leaf_cred_jwk.serialize(private=True))

CREDENTIAL_ISSUER_JWK = JWK(leaf_cred_jwk_prot.serialize(private=True))

issued_jwt = issue_sd_jwt(
    sd_specification,
    settings,
    CREDENTIAL_ISSUER_JWK,
    WALLET_PUBLIC_JWK,
    trust_chain=trust_chain_issuer,
    additional_headers={"typ": "vc+sd-jwt"}
)

adapted_keys = _adapt_keys(
    issuer_key=ISSUER_PRIVATE_JWK,
    holder_key=WALLET_PUBLIC_JWK,
)

sdjwt_at_holder = SDJWTHolder(
    issued_jwt["issuance"],
    serialization_format="compact",
)

red_data = decode_jwt_payload(sign_request_obj.text)
req_nonce = red_data["nonce"]
verifier_id = red_data["client_id"]

sdjwt_at_holder.create_presentation(
    claims_to_disclose={
        'tax_id_code': "TINIT-XXXXXXXXXXXXXXXX",
        'given_name': 'Mario',
        'family_name': 'Rossi'
    },
    nonce=req_nonce,
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

# As it was with the VP envelope
# red_data = decode_jwt_payload(sign_request_obj.text)
# req_nonce = red_data['nonce']

# data = {
#     "iss": "https://wallet-provider.example.org/instance/vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
#     "jti": str(uuid.uuid4()),
#     "aud": "https://relying-party.example.org/callback",
#     "iat": iat_now(),
#     "exp": exp_from_now(minutes=5),
#     "nonce": req_nonce,
#     "vp": sdjwt_at_holder.sd_jwt_presentation,
# }

# vp_token = JWSHelper(WALLET_PRIVATE_JWK).sign(
#     data,
#     protected={"typ": "JWT"}
# )
# End deprecated footprint VP envelop

# take relevant information from RP's EC
rp_ec_jwt = http_user_agent.get(
    f'{IDP_BASEURL}/OpenID4VP/.well-known/openid-federation',
    verify=False
).content.decode()
rp_ec = decode_jwt_payload(rp_ec_jwt)

presentation_definition = rp_ec["metadata"]["wallet_relying_party"]["presentation_definition"]
PresentationDefinition(**presentation_definition)
assert response_uri == rp_ec["metadata"]['wallet_relying_party']["response_uris_supported"][0]

response = {
    "state": red_data['state'],
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


authz_response_ok = http_user_agent.post(
    response_uri,
    verify=False,
    data={'response': encrypted_response},
    timeout=TIMEOUT_S
)
assert 'redirect_uri' in authz_response_ok.content.decode()
callback_uri = json.loads(authz_response_ok.content.decode())['redirect_uri']
satosa_authn_response = http_user_agent.get(
    callback_uri,
    verify=False,
    timeout=TIMEOUT_S
)

assert 'SAMLResponse' in satosa_authn_response.content.decode()
print(satosa_authn_response.content.decode())

soup = BeautifulSoup(satosa_authn_response.content.decode(), features="lxml")
form = soup.find("form")
assert "/saml2" in form["action"]
input_tag = soup.find("input")
assert input_tag["name"] == "SAMLResponse"

lowered = base64.b64decode(input_tag["value"]).lower()
value = BeautifulSoup(lowered, features="xml")
attributes = value.find_all("saml:attribute")
# expect to have a non-empty list of attributes
assert attributes

expected = {
    # https://oidref.com/2.5.4.42
    "urn:oid:2.5.4.42": ISSUER_CONF['sd_specification'].split('!sd given_name:')[1].split('"')[1].lower(),
    # https://oidref.com/2.5.4.4
    "urn:oid:2.5.4.4": ISSUER_CONF['sd_specification'].split('!sd family_name:')[1].split('"')[1].lower()
}

for exp_att_name, exp_att_value in expected.items():
    result_index = -1
    for i, attribute in enumerate(attributes):
        if attribute["name"] == exp_att_name:
            result_index = i
            break
    assert result_index != -1, f"missing attribute with name=[{exp_att_name}] in result set"
    obt_att_value = attributes[result_index].contents[0].contents[0]
    assert exp_att_value == obt_att_value, f"wrong attrirbute parsing expected {exp_att_value}, obtained {obt_att_value}"

print('test passed')
