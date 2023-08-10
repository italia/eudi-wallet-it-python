import requests
import os
import urllib
import datetime

from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.config import SPConfig
from saml2.client import Saml2Client
from saml2.xmldsig import SIG_RSA_SHA256, DIGEST_SHA256
from saml2.saml import (NAMEID_FORMAT_PERSISTENT,
                        NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_UNSPECIFIED)
from saml2.sigver import get_xmlsec_binary
from saml2.metadata import entity_descriptor

from trust_chain_provider import *

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.oauth2.dpop import DPoPIssuer
from pyeudiw.storage.db_engine import DBEngine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BASE = 'http://pyeudiw_demo.example.org'
BASE_URL = '{}/saml2'.format(BASE)

CONFIG_DB = {
  "mongo_db": {
    "cache": {
      "module": "pyeudiw.storage.mongo_cache",
      "class": "MongoCache",
      "init_params": {
        "url": "mongodb://localhost:27017/",
        "conf": {
          "db_name": "eudiw"
        },
        "connection_params": {}
      }
    },
    "storage": {
      "module": "pyeudiw.storage.mongo_storage",
      "class": "MongoStorage",
      "init_params": {
        "url": "mongodb://localhost:27017/",
        "conf": {
          "db_name": "eudiw",
          "db_collection": "sessions",
          "db_sessions_collection": "sessions",
          "db_attestations_collection": "attestations",
          "db_anchors_collection": "anchors"
        },
        "connection_params": {}
      }
    }
  }
}

SAML_CONFIG = {

    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin',
                                        '/usr/bin/xmlsec1']),
    'entityid': '%s/metadata/' % BASE_URL,
    'verify_ssl_cert': False,

    'attribute_map_dir': f"{BASE_DIR}{os.path.sep}attribute-maps",
    'service': {
        'sp': {
            'name': '%s/metadata/' % BASE_URL,

            'name_id_format': [NAMEID_FORMAT_PERSISTENT,
                               NAMEID_FORMAT_TRANSIENT],

            'endpoints': {
                'assertion_consumer_service': [
                    ('%s/acs/' % BASE_URL, BINDING_HTTP_POST),
                    ],
                }, # end endpoints

            'signing_algorithm':  SIG_RSA_SHA256,
            'digest_algorithm':  DIGEST_SHA256,

            "force_authn": True,
            'name_id_format_allow_create': False,


            'want_response_signed': True,
            'authn_requests_signed': True,
            'logout_requests_signed': True,
            'want_assertions_signed': True,

            'only_use_keys_in_metadata': True,

            'allow_unsolicited': True,

            'allow_unknown_attributes': True,

            }, # end sp

    },

    # many metadata, many idp...
    'metadata': {
        # "remote": [
        #     {
        #         "url": "https://localhost:10000/Saml2IDP/metadata",
        #         "disable_ssl_certificate_validation": True,
        #         "check_validity": False,
        #     }
        # ],
        'local': [
            f"{BASE_DIR}{os.path.sep}metadata"
        ],
    },

    # Signing
    'key_file': BASE_DIR + '/private.key',
    'cert_file': BASE_DIR + '/public.cert',

    # own metadata settings
    'contact_person': [
      {'given_name': 'Giuseppe',
       'sur_name': 'De Marco',
       'company': 'Universita della Calabria',
       'email_address': 'giuseppe.demarco@unical.it',
       'contact_type': 'technical'},
      ],
    # you can set multilanguage information here
    'organization': {
      'name': [('Unical', 'it'), ('Unical', 'en')],
      'display_name': [('Unical', 'it'), ('Unical', 'en')],
      'url': [('http://www.ey.it', 'it'), ('http://www.ey.it', 'en')],
      },
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


sp_conf = SPConfig()
sp_conf.load(SAML_CONFIG)

sp_client = Saml2Client(sp_conf)

sp_metadata = entity_descriptor(sp_conf)

# print(sp_metadata)

session_id, result = sp_client.prepare_for_authenticate(
    entityid='https://localhost:10000/Saml2IDP/metadata',
    relay_state='/',
    binding=BINDING_HTTP_REDIRECT
)



req_url = f"{result['headers'][0][1]}&idp_hinting=wallet"

headers_mobile = {'User-Agent' : 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B137 Safari/601.1'}

request_uri = ''
try:
    authn_response = requests.get(
        url = req_url, 
        verify=False, 
        headers=headers_mobile
    )
except requests.exceptions.InvalidSchema as e:
    request_uri = urllib.parse.unquote_plus(e.args[0].split("request_uri=")[1][:-1])

#
db_engine_inst = DBEngine(CONFIG_DB)

entity_id = ta_es['iss']
#TODO
entity_configuration_ta = ta_es

breakpoint()
db_engine_inst.add_anchor(entity_id, entity_configuration_ta, datetime.datetime.now(datetime.timezone.utc))

PRIVATE_JWK = JWK(leaf_wallet_jwk.serialize(private=True))
# PRIVATE_JWK = leaf_wallet_jwk.serialize(private=True)
jwshelper = JWSHelper(PRIVATE_JWK)
wia = jwshelper.sign(
    WALLET_INSTANCE_ATTESTATION,
    protected={
        # 'trust_chain': trust_chain_wallet,
        'trust_chain': trust_chain_wallet,
        'x5c': []
    }
)

dpop_wia = wia
dpop_proof = DPoPIssuer(
        htu=request_uri,
        token=dpop_wia,
        private_jwk=PRIVATE_JWK
).proof
from pyeudiw.oauth2.dpop import DPoPIssuer, DPoPVerifier

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
