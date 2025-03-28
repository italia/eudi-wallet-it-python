import os
import pathlib

from cryptojwt.jwk.ec import new_ec_key

from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.tests.x509.test_x509 import gen_chain

BASE_URL = "https://example.com"
AUTHZ_PAGE = "example.com"
AUTH_ENDPOINT = "https://example.com/auth"
CLIENT_ID = "client_id"

httpc_params = {
    "connection": {"ssl": True},
    "session": {"timeout": 1},
}

_METADATA = {
    "application_type": "web",
    "authorization_encrypted_response_alg": ["RSA-OAEP", "RSA-OAEP-256"],
    "authorization_encrypted_response_enc": [
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ],
    "authorization_signed_response_alg": ["RS256", "ES256"],
    "client_id": f"{BASE_URL}/OpenID4VP",
    "client_name": "Name of an example organization",
    "contacts": ["ops@verifier.example.org"],
    "default_acr_values": [
        "https://www.spid.gov.it/SpidL2",
        "https://www.spid.gov.it/SpidL3",
    ],
    "default_max_age": 1111,
    "id_token_encrypted_response_alg": ["RSA-OAEP", "RSA-OAEP-256"],
    "id_token_encrypted_response_enc": [
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ],
    "id_token_signed_response_alg": ["RS256", "ES256"],
    "response_uris": [f"{BASE_URL}/OpenID4VP/response-uri"],
    "request_uris": [f"{BASE_URL}/OpenID4VP/request-uri"],
    "require_auth_time": True,
    "subject_type": "pairwise",
    "vp_formats": {
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256", "ES384"],
            "kb-jwt_alg_values": ["ES256", "ES384"],
        }
    },
}

CONFIG = {
    "base_url": BASE_URL,
    "ui": {
        "static_storage_url": BASE_URL,
        "template_folder": f"{pathlib.Path().absolute().__str__()}/pyeudiw/tests/satosa/templates",
        "qrcode_template": "qrcode.html",
        "error_url": "https://localhost:9999/error_page.html",
    },
    "endpoints": {
        "pre_request": "/pre-request",
        "response": "/response-uri",
        "request": "/request-uri",
        "status": "/status-uri",
        "get_response": "/get-response",
    },
    "response_code": {
        "sym_key": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    },
    "qrcode": {
        "size": 100,
        "color": "#2B4375",
        "expiration_time": 120,
        "logo_path": "pyeudiw/tests/satosa/static/logo.png",
    },
    "jwt": {"default_sig_alg": "ES256", "default_exp": 6},
    "authorization": {
        "url_scheme": "haip",  # haip://
        "scopes": ["pid-sd-jwt:unique_id+given_name+family_name"],
        "default_acr_value": "https://www.spid.gov.it/SpidL2",
        "expiration_time": 5,  # minutes
        "presentation_definition": [
            {
                "id": "pid-sd-jwt:unique_id+given_name+family_name",
                "input_descriptors": [
                    {
                        "format": {
                            "constraints": {
                                "fields": [
                                    {
                                        "filter": {
                                            "const": "PersonIdentificationData",
                                            "type": "string",
                                        },
                                        "path": ["$.sd-jwt.type"],
                                    },
                                    {
                                        "filter": {"type": "object"},
                                        "path": ["$.sd-jwt.cnf"],
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": ["$.sd-jwt.family_name"],
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": ["$.sd-jwt.given_name"],
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": ["$.sd-jwt.unique_id"],
                                    },
                                ],
                                "limit_disclosure": "required",
                            },
                            "jwt": {"alg": ["EdDSA", "ES256"]},
                        },
                        "id": "sd-jwt",
                    }
                ],
            },
            {
                "id": "mDL-sample-req",
                "input_descriptors": [
                    {
                        "format": {
                            "constraints": {
                                "fields": [
                                    {
                                        "filter": {
                                            "const": "org.iso.18013.5.1.mDL",
                                            "type": "string",
                                        },
                                        "path": ["$.mdoc.doctype"],
                                    },
                                    {
                                        "filter": {
                                            "const": "org.iso.18013.5.1",
                                            "type": "string",
                                        },
                                        "path": ["$.mdoc.namespace"],
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": ["$.mdoc.family_name"],
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": ["$.mdoc.portrait"],
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": ["$.mdoc.driving_privileges"],
                                    },
                                ],
                                "limit_disclosure": "required",
                            },
                            "mso_mdoc": {"alg": ["EdDSA", "ES256"]},
                        },
                        "id": "mDL",
                    }
                ],
            },
        ],
    },
    "user_attributes": {
        "unique_identifiers": ["tax_id_code", "unique_id"],
        "subject_id_random_value": "CHANGEME!",
    },
    "network": {"httpc_params": httpc_params},
    "trust": {
        "direct_trust_sd_jwt_vc": {
            "module": "pyeudiw.trust.handler.direct_trust_sd_jwt_vc",
            "class": "DirectTrustSdJwtVc",
            "config": {
                "jwk_endpoint": "/.well-known/jwt-vc-issuer",
                "httpc_params": {
                    "connection": {"ssl": True},
                    "session": {"timeout": 6},
                },
            },
        },
        "federation": {
            "module": "pyeudiw.trust.handler.federation",
            "class": "FederationHandler",
            "config": {
                "entity_configuration_exp": 600,
                "metadata": _METADATA,
                "metadata_type": "openid_credential_verifier",
                "authority_hints": ["https://trust-anchor.example.org"],
                "trust_anchors": ["https://trust-anchor.example.org"],
                "default_sig_alg": "RS256",
                "federation_jwks": [
                    {
                        "kty": "RSA",
                        "d": "QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7v"
                        "tyCoA-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVG"
                        "H9U3W_djh4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q",
                        "e": "AQAB",
                        "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
                        "n": "utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx"
                        "6nq1uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBK"
                        "woxeRyD3zWE2FXRFBbhKGksMrCGnFDsNl5JTlPjaM3kYyImE941ggcuc495m-Fw",
                        "p": "2zmGXIMCEHPphw778YjVTar1eycih6fFSJ4I4bl1iq167GqO0PjlOx6CZ1-OdBTVU7HfrYRiUK_BnGRdPDn-DQghwwkB79ZdHWL14wXnpB5y-boHz_LxvjsEqXtuQYcIkidOGaMG6"
                        "8XNT1nM4F9a8UKFr5hHYT5_UIQSwsxlRQ0",
                        "q": "2jMFt2iFrdaYabdXuB4QMboVjPvbLA-IVb6_0hSG_-EueGBvgcBxdFGIZaG6kqHqlB7qMsSzdptU0vn6IgmCZnX-Hlt6c5X7JB_q91PZMLTO01pbZ2Bk58GloalCHnw_mjPh0YPvi"
                        "H5jGoWM5RHyl_HDDMI-UeLkzP7ImxGizrM",
                    },
                    {
                        "kty": "EC",
                        "kid": "xPFTWxeGHTVTaDlzGad0MKN5JmWOSnRqEjJCtvQpoyg",
                        "crv": "P-256",
                        "x": "EkMoe7qPLGMydWO_evC3AXEeXJlLQk9tNRkYcpp7xHo",
                        "y": "VLoHFl90D1SdTTjMvNf3WssWiCBXcU1lGNPbOmcCqdU",
                        "d": "oGzjgBbIYNL9opdJ_rDPnCJF89yN8yj8wegdkYfaxw0",
                    },
                ],
                "trust_marks": ["..."],
                "federation_entity_metadata": {
                    "organization_name": "Example RP",
                    "homepage_uri": "https://developers.italia.it",
                    "policy_uri": "https://developers.italia.it/privacy-policy",
                    "tos_uri": "https://developers.italia.it/privacy-policy",
                    "logo_uri": "https://developers.italia.it/assets/img/io-it-logo-white.svg",
                },
            },
        },
        "x509": {
            "module": "pyeudiw.trust.handler.x509",
            "class": "X509Handler",
            "config": {
                "client_id": f"{BASE_URL}/OpenID4VP",
                "relying_party_certificate_chains_by_ca":{
                    "ca.example.com": gen_chain(leaf_cn="example.com"),
                },
                "private_keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": "123114cf-ebef-48d9-9602-3be85e6e12dd",
                        "d": "b41VkvQv083zdtsqX9Q4RqW6DOH7LcSMSSK-KaUi-jtR4SdPkans1vY9QwfZ1gL-iQm0UP50Txow1Xawnh_-O45efpTOJ0sEXno5gXregQQNXxum-ATh7npYTv3Zjfl1lw4GX9UvXwtko3zHA01OtvOdXxtDHtatvoojFEwTisBT5j9f_q7Dmmgmtml17U_M1heANv9O9PqOey2U7_wZRji2lLGpeP7DxeBpTVztyKdnBZCjBnwfyrES3eAPlO5GI3zWAxHuaSsms3F8WQKJqHQs8xDxHpC1MCPMqmnCZnrBxZXxeeg6gMuEJ72RtzziOwH2gr3alND6gpARwwgEYQ",
                        "n": "oV1dBQQpxKhVpJzouceEvuJQ_0nIvK3GVF4FEKRunCWK1amBupkegZgIXq98WsvfNHLwKPhhFXO1unONb44Q51VeFet7ThWyJSB9dhXmr21wvqFA4HVQj4vGPLiGUmacKL-9W4vd_ElLyf1TEtcolUafEI83zfg6bsVkJrwdSRDkxYU5Kh28ayCgoaqXUwLsuR-xT5EiksJESHtqW5_8sqrp5v95UOxxK8NdbEQ54Fr2pfeKQ6Id5VyUlwOnfnV6zgJJ7qBM1NxcyQ7OkQHrh03LfoPF2Hl7-EuZ0ET8p9RVC7eC2NH033O9rSiWljwwsvmRG7nyVN7bkB5wbInp0Q",
                        "e": "AQAB",
                        "p": "0RHnCQZiI6VomMmRcfDyRgqZjUEHLPF17u4TAxqFys3-lgxuRCn8cjXkzJ7t9C0FmGNQy2zrwhQZRUlKotPwB9t0qTRwshqmG40O4EHfdgqu_sqNe8toCJ9xGqkDJFdYvmPy-SkqMYyszRf1GEwMjgj1Ncyx4WciaEbHZUllQo0",
                        "q": "xZYanwkJJGOD4b7Z2PwCA_ubEYU8O2C3UoeINv2P5fXicXRK278o4WelaQBhyvDcPyS3lJyyusB_ro3Fax1fm4IDV1buITar671NzooWKOUQgG0MoVHS8k7qFmGXGDhFBrO_khsvc3FNAjdqkNpH5slo8AwvN2SrbHO3GX6aVVU",
                        "dp": "tk7iJCCI24SVXQYH6k-tNB5yH5ag5zP3Hs5DjeVG3b4bTkSwsofaNs2AIl5EKTRJOMUB4yGrw6U7FAwBJVOib3eSlym_S8-pIUUzv6IxdgGC73M5RMXuhfZi7liLANmZ7QvDCDo5LNP6qy1E8FcAa6qsCKniQydn_X4aydvijNE",
                        "dq": "Ml9mQg1Hq2NDiBXj7BGzYdiPXBQfmvO5SO0MqRhTy0i4hjwjqYo-ndiSrwZN6DMns2Fk_BpG5p2U76dtITXH3hlzSJz88LLDecI1R-akZ6CeaF9kzOvTX7sGqtYOczpFPsQsns8XddL40wvVu0Aq_Id0nV49211q5qdJktJX_lE",
                        "qi": "rQ5SbqNeVrGOZ1rJXWbiAxux_-E1HBunOKWN6HQpoStLpRzJ6zz8aEXhSXMAnbeQOi1ZBS1escmlSupkgz4TEnrhionAJ2orIJ1rOiZIii7stJVkB3fs2LBoxs17Msj9AVrBA-tHhWpoBj63t-ahhEuxhgReq_0DjzQgcP7xUA"
                    }
                ]
            }
        },
   
    },
    "metadata_jwks": [
        {
            "crv": "P-256",
            "d": "KzQBowMMoPmSZe7G8QsdEWc1IvR2nsgE8qTOYmMcLtc",
            "kid": "dDwPWXz5sCtczj7CJbqgPGJ2qQ83gZ9Sfs-tJyULi6s",
            "kty": "EC",
            "x": "TSO-KOqdnUj5SUuasdlRB2VVFSqtJOxuR5GftUTuBdk",
            "y": "ByWgQt1wGBSnF56jQqLdoO1xKUynMY-BHIDB3eXlR7",
        },
        {
            "kty": "RSA",
            "d": "QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7vtyCo"
            "A-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVGH9U3W_dj"
            "h4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q",
            "e": "AQAB",
            "use": "enc",
            "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
            "n": "utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx6nq1"
            "uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBKwoxeRyD3"
            "zWE2FXRFBbhKGksMrCGnFDsNl5JTlPjaM3kYyImE941ggcuc495m-Fw",
            "p": "2zmGXIMCEHPphw778YjVTar1eycih6fFSJ4I4bl1iq167GqO0PjlOx6CZ1-OdBTVU7HfrYRiUK_BnGRdPDn-DQghwwkB79ZdHWL14wXnpB5y-boHz_LxvjsEqXtuQYcIkidOGaMG68XNT"
            "1nM4F9a8UKFr5hHYT5_UIQSwsxlRQ0",
            "q": "2jMFt2iFrdaYabdXuB4QMboVjPvbLA-IVb6_0hSG_-EueGBvgcBxdFGIZaG6kqHqlB7qMsSzdptU0vn6IgmCZnX-Hlt6c5X7JB_q91PZMLTO01pbZ2Bk58GloalCHnw_mjPh0YPviH5jG"
            "oWM5RHyl_HDDMI-UeLkzP7ImxGizrM",
        },
    ],
    "storage": {
        "mongo_db": {
            "cache": {
                "module": "pyeudiw.storage.mongo_cache",
                "class": "MongoCache",
                "init_params": {
                    "url": f"mongodb://{os.getenv('PYEUDIW_MONGO_TEST_AUTH_INLINE', '')}localhost:27017/?timeoutMS=2000",
                    "conf": {"db_name": "eudiw"},
                    "connection_params": {},
                },
            },
            "storage": {
                "module": "pyeudiw.storage.mongo_storage",
                "class": "MongoStorage",
                "init_params": {
                    "url": f"mongodb://{os.getenv('PYEUDIW_MONGO_TEST_AUTH_INLINE', '')}localhost:27017/?timeoutMS=2000",
                    "conf": {
                        "db_name": "test-eudiw",
                        "db_sessions_collection": "sessions",
                        "db_trust_attestations_collection": "trust_attestations",
                        "db_trust_anchors_collection": "trust_anchors",
                        "db_trust_sources_collection": "trust_sources",
                    },
                    "connection_params": {},
                },
            },
        }
    },
    "metadata": _METADATA,
    "credential_presentation_handlers": {
        "max_submission_size": 4096,
        "formats": [
            {
                "module": "pyeudiw.openid4vp.vp_sd_jwt_vc",
                "class": "VpVcSdJwtParserVerifier",
                "format": "dc+sd-jwt",
                "config": {
                    "sig_alg_supported": [
                            "RS256",
                            "RS384",
                            "RS512",
                            "ES256",
                            "ES384",
                            "ES512",
                    ]
                }
            },
            {
                "module": "pyeudiw.openid4vp.vp_mdoc_cbor",
                "class": "VpMDocCbor",
                "format": "mso_mdoc",
            }
        ],
    },
}

CREDENTIAL_ISSUER_ENTITY_ID = "https://issuer.example.com"

MODULE_DIRECT_TRUST_CONFIG = {
    "module": "pyeudiw.trust.default.direct_trust_sd_jwt_vc",
    "class": "DirectTrustSdJwtVc",
    "config": {
        "jwk_endpoint": "/.well-known/jwt-vc-issuer",
        "httpc_params": {"connection": {"ssl": True}, "session": {"timeout": 6}},
    },
}

CONFIG_DIRECT_TRUST = {
    "base_url": BASE_URL,
    "ui": {
        "static_storage_url": BASE_URL,
        "template_folder": f"{pathlib.Path().absolute().__str__()}/pyeudiw/tests/satosa/templates",
        "qrcode_template": "qrcode.html",
        "error_url": "https://localhost:9999/error_page.html",
    },
    "endpoints": {
        "entity_configuration": "/.well-known/openid-federation",
        "pre_request": "/pre-request",
        "response": "/response-uri",
        "request": "/request-uri",
        "status": "/status-uri",
        "get_response": "/get-response",
    },
    "response_code": {
        "sym_key": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    },
    "qrcode": {
        "size": 100,
        "color": "#2B4375",
        "expiration_time": 120,
        "logo_path": "pyeudiw/tests/satosa/static/logo.png",
    },
    "jwt": {"default_sig_alg": "ES256", "default_exp": 6},
    "authorization": {
        "url_scheme": "haip",  # haip://
        "scopes": ["pid-sd-jwt:unique_id+given_name+family_name"],
        "default_acr_value": "https://www.spid.gov.it/SpidL2",
        "expiration_time": 5,  # minutes
        "presentation_definition": [
            {
                "id": "pid-sd-jwt:unique_id+given_name+family_name",
                "input_descriptors": [
                    {
                        "format": {
                            "constraints": {
                                "fields": [
                                    {
                                        "filter": {
                                            "const": "PersonIdentificationData",
                                            "type": "string",
                                        },
                                        "path": ["$.sd-jwt.type"],
                                    },
                                    {
                                        "filter": {"type": "object"},
                                        "path": ["$.sd-jwt.cnf"],
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": ["$.sd-jwt.family_name"],
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": ["$.sd-jwt.given_name"],
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": ["$.sd-jwt.unique_id"],
                                    },
                                ],
                                "limit_disclosure": "required",
                            },
                            "jwt": {"alg": ["EdDSA", "ES256"]},
                        },
                        "id": "sd-jwt",
                    }
                ],
            },
            {
                "id": "mDL-sample-req",
                "input_descriptors": [
                    {
                        "format": {
                            "constraints": {
                                "fields": [
                                    {
                                        "filter": {
                                            "const": "org.iso.18013.5.1.mDL",
                                            "type": "string",
                                        },
                                        "path": ["$.mdoc.doctype"],
                                    },
                                    {
                                        "filter": {
                                            "const": "org.iso.18013.5.1",
                                            "type": "string",
                                        },
                                        "path": ["$.mdoc.namespace"],
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": ["$.mdoc.family_name"],
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": ["$.mdoc.portrait"],
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": ["$.mdoc.driving_privileges"],
                                    },
                                ],
                                "limit_disclosure": "required",
                            },
                            "mso_mdoc": {"alg": ["EdDSA", "ES256"]},
                        },
                        "id": "mDL",
                    }
                ],
            },
        ],
    },
    "user_attributes": {
        "unique_identifiers": ["tax_id_code", "unique_id"],
        "subject_id_random_value": "CHANGEME!",
    },
    "network": {"httpc_params": httpc_params},
    "trust": {"direct_trust_sd_jwt_vc": MODULE_DIRECT_TRUST_CONFIG},
    "metadata_jwks": [
        {
            "crv": "P-256",
            "d": "KzQBowMMoPmSZe7G8QsdEWc1IvR2nsgE8qTOYmMcLtc",
            "kid": "dDwPWXz5sCtczj7CJbqgPGJ2qQ83gZ9Sfs-tJyULi6s",
            "kty": "EC",
            "x": "TSO-KOqdnUj5SUuasdlRB2VVFSqtJOxuR5GftUTuBdk",
            "y": "ByWgQt1wGBSnF56jQqLdoO1xKUynMY-BHIDB3eXlR7",
        },
        {
            "kty": "RSA",
            "d": "QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7vtyCo"
            "A-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVGH9U3W_dj"
            "h4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q",
            "e": "AQAB",
            "use": "enc",
            "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
            "n": "utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx6nq1"
            "uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBKwoxeRyD3"
            "zWE2FXRFBbhKGksMrCGnFDsNl5JTlPjaM3kYyImE941ggcuc495m-Fw",
            "p": "2zmGXIMCEHPphw778YjVTar1eycih6fFSJ4I4bl1iq167GqO0PjlOx6CZ1-OdBTVU7HfrYRiUK_BnGRdPDn-DQghwwkB79ZdHWL14wXnpB5y-boHz_LxvjsEqXtuQYcIkidOGaMG68XNT"
            "1nM4F9a8UKFr5hHYT5_UIQSwsxlRQ0",
            "q": "2jMFt2iFrdaYabdXuB4QMboVjPvbLA-IVb6_0hSG_-EueGBvgcBxdFGIZaG6kqHqlB7qMsSzdptU0vn6IgmCZnX-Hlt6c5X7JB_q91PZMLTO01pbZ2Bk58GloalCHnw_mjPh0YPviH5jG"
            "oWM5RHyl_HDDMI-UeLkzP7ImxGizrM",
        },
    ],
    "storage": {
        "mongo_db": {
            "cache": {
                "module": "pyeudiw.storage.mongo_cache",
                "class": "MongoCache",
                "init_params": {
                    "url": "mongodb://localhost:27017/?timeoutMS=2000",
                    "conf": {"db_name": "eudiw"},
                    "connection_params": {},
                },
            },
            "storage": {
                "module": "pyeudiw.storage.mongo_storage",
                "class": "MongoStorage",
                "init_params": {
                    "url": "mongodb://localhost:27017/?timeoutMS=2000",
                    "conf": {
                        "db_name": "test-eudiw",
                        "db_sessions_collection": "sessions",
                        "db_trust_attestations_collection": "trust_attestations",
                        "db_trust_anchors_collection": "trust_anchors",
                    },
                    "connection_params": {},
                },
            },
        }
    },
    "metadata": {
        "application_type": "web",
        "authorization_encrypted_response_alg": ["RSA-OAEP", "RSA-OAEP-256"],
        "authorization_encrypted_response_enc": [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ],
        "authorization_signed_response_alg": ["RS256", "ES256"],
        "client_id": f"{BASE_URL}/OpenID4VP",
        "client_name": "Name of an example organization",
        "contacts": ["ops@verifier.example.org"],
        "default_acr_values": [
            "https://www.spid.gov.it/SpidL2",
            "https://www.spid.gov.it/SpidL3",
        ],
        "default_max_age": 1111,
        "id_token_encrypted_response_alg": ["RSA-OAEP", "RSA-OAEP-256"],
        "id_token_encrypted_response_enc": [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ],
        "id_token_signed_response_alg": ["RS256", "ES256"],
        "response_uris": [f"{BASE_URL}/OpenID4VP/response-uri"],
        "request_uris": [f"{BASE_URL}/OpenID4VP/request-uri"],
        "require_auth_time": True,
        "subject_type": "pairwise",
        "vp_formats": {
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256", "ES384"],
                "kb-jwt_alg_values": ["ES256", "ES384"],
            }
        },
    },
}

CREDENTIAL_ISSUER_CONF = {
    "sd_specification": """
        user_claims:
            !sd unique_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            !sd given_name: "Mario"
            !sd family_name: "Rossi"
            !sd birthdate: "1980-01-10"
            !sd place_of_birth:
                country: "IT"
                locality: "Rome"
            !sd tax_id_code: "TINIT-XXXXXXXXXXXXXXXX"

        holder_disclosed_claims:
            { "given_name": "Mario", "family_name": "Rossi", "place_of_birth": {country: "IT", locality: "Rome"} }

        key_binding: True
    """
}


INTERNAL_ATTRIBUTES: dict = {"attributes": {}}


PRIVATE_JWK = new_ec_key("P-256")
PUBLIC_JWK = PRIVATE_JWK.serialize(private=False)


WALLET_INSTANCE_ATTESTATION = {
    "iss": "https://wallet-provider.example.org",
    "sub": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
    "type": "WalletInstanceAttestation",
    "policy_uri": "https://wallet-provider.example.org/privacy_policy",
    "tos_uri": "https://wallet-provider.example.org/info_policy",
    "logo_uri": "https://wallet-provider.example.org/logo.svg",
    "aal": "https://wallet-provider.example.org/LoA/basic",
    "cnf": {"jwk": PUBLIC_JWK},
    "authorization_endpoint": "haip:",
    "response_types_supported": ["vp_token"],
    "vp_formats_supported": {
        "jwt_vp_json": {"alg_values_supported": ["ES256"]},
        "jwt_vc_json": {"alg_values_supported": ["ES256"]},
    },
    "request_object_signing_alg_values_supported": ["ES256"],
    "presentation_definition_uri_supported": False,
    "iat": iat_now(),
    "exp": exp_from_now(),
}
