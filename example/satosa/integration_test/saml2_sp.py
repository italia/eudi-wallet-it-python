import os

from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.config import SPConfig
from saml2.client import Saml2Client
from saml2.xmldsig import SIG_RSA_SHA256, DIGEST_SHA256
from saml2.saml import(
    NAMEID_FORMAT_PERSISTENT,
    NAMEID_FORMAT_TRANSIENT,
    NAMEID_FORMAT_UNSPECIFIED
)
from saml2.sigver import get_xmlsec_binary
from saml2.metadata import entity_descriptor


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = 'http://pyeudiw_demo.example.org'
BASE_URL = '{}/saml2'.format(BASE)
IDP_ENTITYID = 'https://localhost:10000/Saml2IDP/metadata'

SAML_CONFIG = {

    'debug' : True,
    'xmlsec_binary': get_xmlsec_binary(
        [
            '/opt/local/bin',
            '/usr/bin/xmlsec1'
        ]
    ),
    'entityid': '%s/metadata/' % BASE_URL,
    'verify_ssl_cert': False,

    'attribute_map_dir': f"{BASE_DIR}{os.path.sep}attribute-maps",
    'service': {
        'sp': {
            'name': '%s/metadata/' % BASE_URL,

            'name_id_format': [
                NAMEID_FORMAT_PERSISTENT,
                NAMEID_FORMAT_TRANSIENT
            ],
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

    'metadata': {
        # "remote": [
        #     {
        #         "url": IDP_ENTITYID,
        #         "disable_ssl_certificate_validation": True,
        #         "check_validity": False,
        #     }
        # ],
        
        # satosa saml2 frontend metadata
        'local': [
            f"{BASE_DIR}{os.path.sep}metadata"
        ],
    },

    # Signing
    'key_file': BASE_DIR + '/certs/private.key',
    'cert_file': BASE_DIR + '/certs/public.cert',

    # own metadata settings
    'contact_person': [
      {'given_name': 'Giuseppe',
       'sur_name': 'De Marco',
       'company': 'A.C.M.E.',
       'email_address': 'demarcog83@gmail.com',
       'contact_type': 'technical'},
      ],
    # you can set multilanguage information here
    'organization': {
      'name': [('A.C.M.E.', 'it'), ('A.C.M.E.', 'en')],
      'display_name': [('A.C.M.E.', 'it'), ('A.C.M.E.', 'en')],
      'url': [('http://www.ey.it', 'it'), ('http://www.ey.it', 'en')],
      },
}

sp_conf = SPConfig()
sp_conf.load(SAML_CONFIG)
sp_client = Saml2Client(sp_conf)
sp_metadata = entity_descriptor(sp_conf)

session_id, saml2_request = sp_client.prepare_for_authenticate(
    entityid=IDP_ENTITYID,
    relay_state='/',
    binding=BINDING_HTTP_REDIRECT
)

print(sp_metadata)
