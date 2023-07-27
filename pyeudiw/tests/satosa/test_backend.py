import base64
import json
import pathlib
import pytest
import urllib.parse

from bs4 import BeautifulSoup

from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.oauth2.dpop import DPoPIssuer
from pyeudiw.satosa.backend import OpenID4VPBackend
from pyeudiw.jwt import JWSHelper, unpad_jwt_header
from pyeudiw.jwk import JWK
from pyeudiw.tools.utils import iat_now

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State
from unittest.mock import Mock


BASE_URL = "https://example.com"
AUTHZ_PAGE = "example.com"
AUTH_ENDPOINT = "https://example.com/auth"
CLIENT_ID = "client_id"

CONFIG = {
    "base_url": BASE_URL,


    "ui": {
        "static_storage_url": BASE_URL,
        "template_folder": f"{pathlib.Path().absolute().__str__()}/pyeudiw/tests/satosa/templates",
        "qrcode_template": "qrcode.html",
        "error_template": "error.html",
        "error_url": "https://localhost:9999/error_page.html"
    },

    "endpoints": {
        "entity_configuration": "/OpenID4VP/.well-known/openid-federation",
        "pre_request": "/OpenID4VP/pre-request",
        "redirect": "/OpenID4VP/redirect_uri",
        "request": "/OpenID4VP/request_uri",
    },
    "qrcode_settings": {
        "size": 100,
        "color": "#2B4375",
        "logo_path": None,
        "use_zlib": True
    },
    "jwt_settings": {
        "default_sig_alg": "ES256",
        "default_exp": 6
    },
    "authorization": {
        "url_scheme": "eudiw",  # eudiw://
        "scopes": ["pid-sd-jwt:unique_id+given_name+family_name"],
    },
    "federation": {
        "metadata_type": "wallet_relying_party",
        "federation_authorities": [
            "https://localhost:8000"
        ],
        "default_sig_alg": "RS256",
        "federation_jwks": [
            {
                "kty": "RSA",
                "d": "QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7vtyCoA-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVGH9U3W_djh4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q",
                "e": "AQAB",
                "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
                "n": "utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx6nq1uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBKwoxeRyD3zWE2FXRFBbhKGksMrCGnFDsNl5JTlPjaM3kYyImE941ggcuc495m-Fw",
                "p": "2zmGXIMCEHPphw778YjVTar1eycih6fFSJ4I4bl1iq167GqO0PjlOx6CZ1-OdBTVU7HfrYRiUK_BnGRdPDn-DQghwwkB79ZdHWL14wXnpB5y-boHz_LxvjsEqXtuQYcIkidOGaMG68XNT1nM4F9a8UKFr5hHYT5_UIQSwsxlRQ0",
                "q": "2jMFt2iFrdaYabdXuB4QMboVjPvbLA-IVb6_0hSG_-EueGBvgcBxdFGIZaG6kqHqlB7qMsSzdptU0vn6IgmCZnX-Hlt6c5X7JB_q91PZMLTO01pbZ2Bk58GloalCHnw_mjPh0YPviH5jGoWM5RHyl_HDDMI-UeLkzP7ImxGizrM"
            }
        ],
        "trust_marks": [
            "..."
        ]
    },
    "metadata_jwks": [
        {
            "crv": "P-256",
            "d": "KzQBowMMoPmSZe7G8QsdEWc1IvR2nsgE8qTOYmMcLtc",
            "kid": "dDwPWXz5sCtczj7CJbqgPGJ2qQ83gZ9Sfs-tJyULi6s",
            "kty": "EC",
            "x": "TSO-KOqdnUj5SUuasdlRB2VVFSqtJOxuR5GftUTuBdk",
            "y": "ByWgQt1wGBSnF56jQqLdoO1xKUynMY-BHIDB3eXlR7"
        }
    ],
    "metadata": {
        "application_type": "web",
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
        "authorization_signed_response_alg": [
            "RS256",
            "ES256"
        ],
        "client_id": f"{BASE_URL}/OpenID4VP",
        "client_name": "Name of an example organization",
        "contacts": [
            "ops@verifier.example.org"
        ],
        "default_acr_values": [
            "https://www.spid.gov.it/SpidL2",
            "https://www.spid.gov.it/SpidL3"
        ],
        "default_max_age": 1111,
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
        "id_token_signed_response_alg": [
            "RS256",
            "ES256"
        ],
        "presentation_definitions": [
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
                                            "type": "string"
                                        },
                                        "path": [
                                            "$.sd-jwt.type"
                                        ]
                                    },
                                    {
                                        "filter": {
                                            "type": "object"
                                        },
                                        "path": [
                                            "$.sd-jwt.cnf"
                                        ]
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": [
                                            "$.sd-jwt.family_name"
                                        ]
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": [
                                            "$.sd-jwt.given_name"
                                        ]
                                    },
                                    {
                                        "intent_to_retain": "true",
                                        "path": [
                                            "$.sd-jwt.unique_id"
                                        ]
                                    }
                                ],
                                "limit_disclosure": "required"
                            },
                            "jwt": {
                                "alg": [
                                    "EdDSA",
                                    "ES256"
                                ]
                            }
                        },
                        "id": "sd-jwt"
                    }
                ]
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
                                            "type": "string"
                                        },
                                        "path": [
                                            "$.mdoc.doctype"
                                        ]
                                    },
                                    {
                                        "filter": {
                                            "const": "org.iso.18013.5.1",
                                            "type": "string"
                                        },
                                        "path": [
                                            "$.mdoc.namespace"
                                        ]
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": [
                                            "$.mdoc.family_name"
                                        ]
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": [
                                            "$.mdoc.portrait"
                                        ]
                                    },
                                    {
                                        "intent_to_retain": "false",
                                        "path": [
                                            "$.mdoc.driving_privileges"
                                        ]
                                    }
                                ],
                                "limit_disclosure": "required"
                            },
                            "mso_mdoc": {
                                "alg": [
                                    "EdDSA",
                                    "ES256"
                                ]
                            }
                        },
                        "id": "mDL"
                    }
                ]
            }
        ],
        "redirect_uris": [
            f"{BASE_URL}/OpenID4VP/redirect_uri"
        ],
        "request_uris": [
            f"{BASE_URL}/OpenID4VP/request_uri"
        ],
        "require_auth_time": True,
        "subject_type": "pairwise",
        "vp_formats": {
            "jwt_vp_json": {
                "alg": [
                    "EdDSA",
                    "ES256K"
                ]
            }
        }
    }
}


INTERNAL_ATTRIBUTES: dict = {
    'attributes': {}
}


PRIVATE_JWK = JWK()
PUBLIC_JWK = PRIVATE_JWK.public_key


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
        "jwk": PUBLIC_JWK
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

class TestOpenID4VPBackend:
    @pytest.fixture(autouse=True)
    def create_backend(self):
        self.backend = OpenID4VPBackend(
            Mock(), INTERNAL_ATTRIBUTES, CONFIG, BASE_URL, "name")

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]}
            }
        }

    @pytest.fixture
    def context(self):
        context = Context()
        context.state = State()
        return context

    def test_backend_init(self):
        assert self.backend.name == "name"

    def test_register_endpoints(self):
        url_map = self.backend.register_endpoints()
        assert len(url_map) == 4
        assert url_map[0][0] == '^' + \
            CONFIG['endpoints']['entity_configuration'].lstrip('/') + '$'
        assert url_map[1][0] == '^' + \
            CONFIG['endpoints']['pre_request'].lstrip('/') + '$'
        assert url_map[2][0] == '^' + \
            CONFIG['endpoints']['redirect'].lstrip('/') + '$'
        assert url_map[3][0] == '^' + \
            CONFIG['endpoints']['request'].lstrip('/') + '$'

    def test_entity_configuration(self):
        entity_config = self.backend.entity_configuration_endpoint(None)
        assert entity_config
        assert entity_config.status == "200"
        assert entity_config.message

    def test_pre_request_endpoint(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(
            context, internal_data)
        assert pre_request_endpoint
        assert pre_request_endpoint.status == "200"
        assert pre_request_endpoint.message

        assert "src='data:image/svg+xml;base64," in pre_request_endpoint.message

        soup = BeautifulSoup(pre_request_endpoint.message, 'html.parser')
        # get the img tag with src attribute starting with data:image/svg+xml;base64,
        img_tag = soup.find(
            lambda tag: tag.name == 'img' and tag.get('src', '').startswith('data:image/svg+xml;base64,'))
        assert img_tag
        # get the src attribute
        src = img_tag['src']
        # remove the data:image/svg+xml;base64, part
        data = src.replace('data:image/svg+xml;base64,', '')
        # decode the base64 data
        decoded = base64.b64decode(data).decode("utf-8")

        svg = BeautifulSoup(decoded, features="xml")
        assert svg
        assert svg.find("svg")
        assert svg.find_all("svg:rect")

    def test_pre_request_endpoint_mobile(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(
            context, internal_data)
        assert pre_request_endpoint
        assert "302" in pre_request_endpoint.status

        assert f"{CONFIG['authorization']['url_scheme']}://authorize" in pre_request_endpoint.message

        unquoted = urllib.parse.unquote(
            pre_request_endpoint.message, encoding='utf-8', errors='replace')
        parsed = urllib.parse.urlparse(unquoted)

        assert parsed.scheme == "eudiw"
        assert parsed.netloc == "authorize"
        assert parsed.path == ""
        assert parsed.query

        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["client_id"][0] == CONFIG["metadata"]["client_id"]
        assert qs["request_uri"][0] == CONFIG["metadata"]["request_uris"][0]

    def test_redirect_endpoint(self, context):

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["redirect_uris"][0]

        redirect_endpoint = self.backend.redirect_endpoint(context)
        assert redirect_endpoint
        # TODO any additional checks after the backend returned the user attributes to satosa core


    def test_request_endpoint(self, context):

        jwshelper = JWSHelper(PRIVATE_JWK)
        wia = jwshelper.sign(
            WALLET_INSTANCE_ATTESTATION,
            protected={'trust_chain': [], 'x5c': []}
        )

        dpop_wia = wia
        dpop_proof = DPoPIssuer(
            htu=CONFIG['metadata']['request_uris'][0],
            token=dpop_wia,
            private_jwk=PRIVATE_JWK
        ).proof

        context.http_headers = dict(
            HTTP_AUTHORIZATION=f"DPoP {dpop_wia}",
            HTTP_DPOP=dpop_proof
        )

        request_endpoint = self.backend.request_endpoint(context)

        assert request_endpoint
        assert request_endpoint.status == "200"
        assert request_endpoint.message

        msg = json.loads(request_endpoint.message)
        assert msg["response"]

        # TODO assertion su JWS decodificato
        # ...
        header = unpad_jwt_header(msg["response"])
        payload = unpad_jwt_payload(msg["response"])
        print()
        print("header", header)
        print("payload", payload)

    def test_handle_error(self, context):
        error_message = "Error message!"
        error_resp = self.backend.handle_error(context, error_message)
        assert error_resp.status == "500"
        assert error_resp.message
        err = json.loads(error_resp.message)
        assert err["message"] == error_message
