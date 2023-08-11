import requests
import os
import urllib
import datetime

from trust_chain_provider import (
    EXP,
    leaf_wallet_jwk,
    trust_chain_issuer,
    trust_chain_wallet,
    ta_ec
)

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.oauth2.dpop import DPoPIssuer, DPoPVerifier
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.utils import iat_now

from saml2_sp import saml2_request


CONFIG_DB = {
  "mongo_db": {
    "storage": {
      "module": "pyeudiw.storage.mongo_storage",
      "class": "MongoStorage",
      "init_params": {
        "url": "mongodb://localhost:27017/",
        "conf": {
          "db_name": "eudiw",
          "db_sessions_collection": "sessions",
          "db_trust_attestations_collection": "trust_attestations",
          "db_trust_anchors_collection": "trust_anchors"
        },
        "connection_params": {}
      }
    }
  }
}


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
        "jwk": leaf_wallet_jwk.serialize()
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

req_url = f"{saml2_request['headers'][0][1]}&idp_hinting=wallet"
headers_mobile = {
    'User-Agent' : 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B137 Safari/601.1'
}

request_uri = ''
try:
    authn_response = requests.get(
        url = req_url, 
        verify=False, 
        headers=headers_mobile
    )
except requests.exceptions.InvalidSchema as e:
    request_uri = urllib.parse.unquote_plus(e.args[0].split("request_uri=")[1][:-1])

# Put the trust anchor EC and the trust chains related to the credential issuer and the wallet provider in the trust storage
db_engine_inst = DBEngine(CONFIG_DB)

db_engine_inst.add_anchor(
    ta_ec['iss'], 
    ta_ec, 
    datetime.datetime.now().isoformat()
)

WALLET_PRIVATE_JWK = JWK(leaf_wallet_jwk.serialize(private=True))
# PRIVATE_JWK = leaf_wallet_jwk.serialize(private=True)
jwshelper = JWSHelper(WALLET_PRIVATE_JWK)
dpop_wia = jwshelper.sign(
    WALLET_INSTANCE_ATTESTATION,
    protected={
        'trust_chain': trust_chain_wallet,
        'typ': "va+jwt"
    }
)

dpop_proof = DPoPIssuer(
        htu=request_uri,
        token=dpop_wia,
        private_jwk=WALLET_PRIVATE_JWK
).proof

dpop_test = DPoPVerifier(
    public_jwk=leaf_wallet_jwk.serialize(),
    http_header_authz=f"DPoP {dpop_wia}",
    http_header_dpop=dpop_proof
)

print(f"dpop is valid: {dpop_test.is_valid}")

http_headers = {
    "AUTHORIZATION":f"DPoP {dpop_wia}",
    "DPOP":dpop_proof
}

#  
sign_request_obj = requests.get(request_uri, verify=False, headers=http_headers)

print(sign_request_obj)
