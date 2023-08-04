import copy
import uuid
import unittest.mock as mock
from unittest.mock import Mock
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
import pyeudiw.federation.trust_chain_validator as tcv_test


# pip install cryptojwt
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import JWS

from pyeudiw.tools.utils import iat_now, exp_from_now

from pyeudiw.federation.schema import is_es

# Create private keys
leaf_jwk = new_rsa_key()
intermediate_jwk = new_rsa_key()
ta_jwk = new_rsa_key()

NOW = iat_now()
EXP = exp_from_now(5)

# Define Entity Configurations
leaf_ec = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://rp.example.it",
    "sub": "https://rp.example.it",
    'jwks': {"keys": []},
    "metadata": {
        "wallet_relying_party": {
            "application_type": "web",
            "client_id": "https://rp.example.it",
            "client_name": "Name of an example organization",
            'jwks': {"keys": []},
            "contacts": [
                "ops@verifier.example.org"
            ],

            "request_uris": [
                "https://verifier.example.org/request_uri"
            ],
            "redirect_uris": [
                "https://verifier.example.org/callback"
            ],

            "default_acr_values": [
                "https://www.spid.gov.it/SpidL2",
                "https://www.spid.gov.it/SpidL3"
            ],

            "vp_formats": {
                "jwt_vp_json": {
                    "alg": [
                        "EdDSA",
                        "ES256K"
                    ]
                }
            },
            "presentation_definitions": [
                {
                    "id": "pid-sd-jwt:unique_id+given_name+family_name",
                    "input_descriptors": [
                          {
                              "id": "sd-jwt",
                              "format": {
                                  "jwt": {
                                    "alg": [
                                        "EdDSA",
                                        "ES256"
                                    ]
                                  },
                                  "constraints": {
                                      "limit_disclosure": "required",
                                      "fields": [
                                          {
                                              "path": [
                                                  "$.sd-jwt.type"
                                              ],
                                              "filter": {
                                                  "type": "string",
                                                  "const": "PersonIdentificationData"
                                              }
                                          },
                                          {
                                              "path": [
                                                  "$.sd-jwt.cnf"
                                              ],
                                              "filter": {
                                                  "type": "object",
                                              }
                                          },
                                          {
                                              "path": [
                                                  "$.sd-jwt.family_name"
                                              ],
                                              "intent_to_retain": "true"
                                          },
                                          {
                                              "path": [
                                                  "$.sd-jwt.given_name"
                                              ],
                                              "intent_to_retain": "true"
                                          },
                                          {
                                              "path": [
                                                  "$.sd-jwt.unique_id"
                                              ],
                                              "intent_to_retain": "true"
                                          }
                                      ]
                                  }
                              }
                          }
                    ]
                },
            ],

            "default_max_age": 1111,

            # JARM related
            "authorization_signed_response_alg": [
                "RS256",
                "ES256"
            ],
            "authorization_encrypted_response_alg": [
                "RSA-OAEP",
                "RSA-OAEP-256"
            ],
            "authorization_encrypted_response_enc": [
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
                "A128GCM",
                "A192GCM",
                "A256GCM"
            ],

            # SIOPv2 related
            "subject_type": "pairwise",
            "require_auth_time": True,
            "id_token_signed_response_alg": [
                "RS256",
                "ES256"
            ],
            "id_token_encrypted_response_alg": [
                "RSA-OAEP",
                "RSA-OAEP-256"
            ],
            "id_token_encrypted_response_enc": [
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
                "A128GCM",
                "A192GCM",
                "A256GCM"
            ],
        },
        "federation_entity": {
            "organization_name": "OpenID Wallet Verifier example",
            "homepage_uri": "https://verifier.example.org/home",
            "policy_uri": "https://verifier.example.org/policy",
            "logo_uri": "https://verifier.example.org/static/logo.svg",
            "contacts": [
                "tech@verifier.example.org"
            ]
        }
    },
    "authority_hints": [
        "https://registry.eudi-wallet.example.it"
    ]
}


intermediate_ec = {
    "exp": EXP,
    "iat": NOW,
    'iss': 'https://intermediate.eidas.example.org',
    'sub': 'https://intermediate.eidas.example.org',
    'jwks': {"keys": []},
    'metadata': {'federation_entity': {'contacts': ['soggetto@intermediate.eidas.example.it'],
                                       'federation_fetch_endpoint': 'https://intermediate.eidas.example.org/fetch/',
                                       'federation_resolve_endpoint': 'https://intermediate.eidas.example.org/resolve/',
                                       'federation_list_endpoint': 'https://intermediate.eidas.example.org/list/',
                                       'homepage_uri': 'https://soggetto.intermediate.eidas.example.it',
                                       'name': 'Example Intermediate intermediate.eidas.example'}},
    'trust_marks': [{'id': 'https://registry.gov.org/intermediate/private/full/',
                     'trust_mark': 'eyJh …'}],
    'authority_hints': ['https://registry.eidas.trust-anchor.example.eu']}


ta_ec = {
    "exp": EXP,
    "iat": NOW,
    'iss': 'https://registry.eidas.trust-anchor.example.eu/',
    'sub': 'https://registry.eidas.trust-anchor.example.eu/',
    'jwks': {"keys": []},
    'metadata': {'federation_entity': {'organization_name': 'example TA',
                                       'contacts': ['tech@eidas.trust-anchor.example.eu'],
                                       'homepage_uri': 'https://registry.eidas.trust-anchor.example.eu/',
                                       'logo_uri': 'https://registry.eidas.trust-anchor.example.eu/static/svg/logo.svg',
                                       'federation_fetch_endpoint': 'https://registry.eidas.trust-anchor.example.eu/fetch/',
                                       'federation_resolve_endpoint': 'https://registry.eidas.trust-anchor.example.eu/resolve/',
                                       'federation_list_endpoint': 'https://registry.eidas.trust-anchor.example.eu/list/',
                                       'federation_trust_mark_status_endpoint': 'https://registry.eidas.trust-anchor.example.eu/trust_mark_status/'}},
    'trust_marks_issuers': {'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/public/': ['https://registry.spid.eidas.trust-anchor.example.eu/',
                                                                                                            'https://public.intermediary.spid.org/'],
                            'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/private/': ['https://registry.spid.eidas.trust-anchor.example.eu/',
                                                                                                             'https://private.other.intermediary.org/']},
    'constraints': {'max_path_length': 1}}

# place example keys
leaf_ec["jwks"]['keys'] = [leaf_jwk.serialize()]
leaf_ec['metadata']['wallet_relying_party']["jwks"]['keys'] = [
    leaf_jwk.serialize()]

intermediate_ec["jwks"]['keys'] = [intermediate_jwk.serialize()]
ta_ec["jwks"]['keys'] = [ta_jwk.serialize()]

# pubblica: dict = privata.serialize()
# privata_dict: dict = privata.to_dict()

# Define Entity Statements
intermediate_es = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://intermediate.eidas.example.org",
    "sub": "https://rp.example.org",
    'jwks': {"keys": []},
    "metadata_policy": {
        "openid_relying_party": {
            "scopes": {
                "subset_of": [
                    "eu.europa.ec.eudiw.pid.1,  eu.europa.ec.eudiw.pid.it.1"
                ]
            },
            "request_authentication_methods_supported": {
                "one_of": ["request_object"]
            },
            "request_authentication_signing_alg_values_supported": {
                "subset_of": ["RS256", "RS512", "ES256", "ES512", "PS256", "PS512"]
            }
        }
    }
}

# the leaf publishes the leaf public key
intermediate_es["jwks"]['keys'] = [leaf_jwk.serialize()]


ta_es = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://trust-anchor.example.eu",
    "sub": "https://intermediate.eidas.example.org",
    'jwks': {"keys": []},
    "trust_marks": [
        {
            "id": "https://trust-anchor.example.eu/federation_entity/that-profile",
            "trust_mark": "eyJhb …"
        }
    ]
}

# the ta publishes the intermediate public key
ta_es["jwks"]['keys'] = [intermediate_jwk.serialize()]


leaf_signer = JWS(leaf_ec, alg="RS256", typ="application/entity-statement+jwt")
leaf_ec_signed = leaf_signer.sign_compact([leaf_jwk])

intermediate_signer = JWS(intermediate_es, alg="RS256",
                          typ="application/entity-statement+jwt")
intermediate_es_signed = intermediate_signer.sign_compact([intermediate_jwk])

ta_signer = JWS(ta_es, alg="RS256", typ="application/entity-statement+jwt")
ta_es_signed = ta_signer.sign_compact([ta_jwk])

trust_chain = [
    leaf_ec_signed,
    intermediate_es_signed,
    ta_es_signed
]


def test_is_valid():
    assert StaticTrustChainValidator(
        trust_chain, [ta_jwk.serialize()]).is_valid


invalid_intermediate = copy.deepcopy(intermediate_es)
invalid_leaf_jwk = copy.deepcopy(leaf_jwk.serialize())
invalid_leaf_jwk["kid"] = str(uuid.uuid4())

invalid_intermediate["jwks"]['keys']  = [invalid_leaf_jwk]

intermediate_signer = JWS(invalid_intermediate, alg="RS256",
                          typ="application/entity-statement+jwt")
invalid_intermediate_es_signed = intermediate_signer.sign_compact([intermediate_jwk])

invalid_trust_chain = [
    leaf_ec_signed,
    invalid_intermediate_es_signed,
    ta_es_signed
]

def test_is_valid_equals_false():
    assert StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()]).is_valid == False
    
    
def test_retrieve_ec():
    tcv_test.get_entity_configurations = Mock(return_value=[leaf_ec_signed])
        
    assert tcv_test.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()])._retrieve_ec("https://trust-anchor.example.eu") == leaf_ec_signed
    
def test_retrieve_ec_fails():
    tcv_test.get_entity_configurations = Mock(return_value=[])
    
    try:
        StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()])._retrieve_ec("https://trust-anchor.example.eu")
    except tcv_test.HttpError as e:
        return
    
def test_retrieve_es():
    tcv_test.get_entity_statements = Mock(return_value=ta_es)
        
    assert tcv_test.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()])._retrieve_es("https://trust-anchor.example.eu", "https://trust-anchor.example.eu") == ta_es
    
def test_retrieve_es_output_is_none():
    tcv_test.get_entity_statements = Mock(return_value=None)
    
    assert tcv_test.StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()])._retrieve_es("https://trust-anchor.example.eu", "https://trust-anchor.example.eu") == None
    
def test_update_st_ec_case():    
    def mock_method(*args, **kwargs):
        if args[0] == "https://rp.example.it":
            return [leaf_ec_signed]
        
        raise Exception("Wrong issuer")
    
    with mock.patch.object(tcv_test, "get_entity_configurations", mock_method):
        assert tcv_test.StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()])._update_st(leaf_ec_signed) == leaf_ec_signed
        
def test_update_st_es_case_source_endpoint():    
    ta_es = {
        "exp": EXP,
        "iat": NOW,
        "iss": "https://trust-anchor.example.eu",
        "sub": "https://intermediate.eidas.example.org",
        'jwks': {"keys": []},
        "source_endpoint": "https://rp.example.it"
    }    
    
    ta_signer = JWS(ta_es, alg="RS256", typ="application/entity-statement+jwt")
    ta_es_signed = ta_signer.sign_compact([ta_jwk])
    
    def mock_method(*args, **kwargs):        
        if args[0] == "https://rp.example.it":
            return leaf_ec_signed
        
        raise Exception("Wrong issuer")
    
    with mock.patch.object(tcv_test, "get_entity_statements", mock_method):
        assert tcv_test.StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()])._update_st(ta_es_signed) == leaf_ec_signed