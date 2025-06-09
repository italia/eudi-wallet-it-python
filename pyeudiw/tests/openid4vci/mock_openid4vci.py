import copy
import uuid

from satosa.context import Context

from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, FORM_URLENCODED
from pyeudiw.tools.validation import OAUTH_CLIENT_ATTESTATION_POP_HEADER, OAUTH_CLIENT_ATTESTATION_HEADER

MOCK_PYEUDIW_FRONTEND_CONFIG = {
    "endpoints": {
        "par": {
            "module": "pyeudiw.openid4vci.endpoints.pushed_authorization_request_endpoint",
            "class": "ParHandler",
            "path": "/par"
        },
        "credential_offer": {
            "module": "pyeudiw.openid4vci.endpoints.credential_offer_endpoint",
            "class": "CredentialOfferHandler",
            "path": "/credential"
        },
        "authorization_endpoint": {
            "module": "pyeudiw.openid4vci.endpoints.authorization_endpoint",
            "class": "AuthorizationHandler",
            "path": "/authorization"
        },
        "token_endpoint": {
            "module": "pyeudiw.openid4vci.endpoints.token_endpoint",
            "class": "TokenHandler",
            "path": "/token"
        },
        "nonce_endpoint": {
            "module": "pyeudiw.openid4vci.endpoints.nonce_endpoint",
            "class": "NonceHandler",
            "path": "/nonce-endpoint"
        },
        "credential_endpoint": {
            "module": "pyeudiw.openid4vci.endpoints.credential_endpoint",
            "class": "CredentialHandler",
            "path": "/credential"
        },
        "deferred_credential_endpoint": {
            "module": "pyeudiw.openid4vci.endpoints.deferred_credential_endpoint",
            "class": "DeferredCredentialHandler",
            "path": "/deferred-credential"
        },
        "notification_endpoint": {
            "module": "pyeudiw.openid4vci.endpoints.notification_endpoint",
            "class": "NotificationHandler",
            "path": "/notification"
        }
    },
    "jwt": {
        "default_sig_alg": "ES256",
        "default_enc_alg": "RSA-OAEP",
        "default_enc_enc": "A256CBC-HS512",
        "default_exp": 6,
        "enc_alg_supported": [
            "RSA-OAEP",
            "RSA-OAEP-256",
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW"
        ],
        "enc_enc_supported": [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM"
        ],
        "sig_alg_supported": [
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512"
        ],
        "access_token_exp": 90,
        "refresh_token_exp": 120,
        "par_exp": 90
    },
    "metadata": {
        "oauth_authorization_server": {
            "response_types_supported": ["code"],
            "response_modes_supported": [
                "form_post.jwt",
                "query"
            ],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["scope1", "scope2", "openid"]
        },
        "openid_credential_issuer" : {
            "credential_configurations_supported": {
                "dc_sd_jwt_EuropeanDisabilityCard" :{
                    "format": "dc+sd-jwt",
                    "scope": "EuropeanDisabilityCard"
                },
                "dc_sd_jwt_mDL":{
                    "scope": "mDL",
                    "cryptographic_binding_methods_supported": [
                        "jwk"
                    ]
                }
            },
            "authorization_servers": [],
            "credential_issuer":"",
        }
    },
    "user_storage": {
        "storage": {
            "module": "pyeudiw.storage.user_storage",
            "class": "UserStorage",
            "init_params": {
                "url": "mongodb://satosa-mongo:27017",
                "conf": {
                    "db_name": "eudiw",
                    "db_sessions_collection": "sessions",
                    "db_trust_attestations_collection": "trust_attestations",
                    "db_trust_anchors_collection": "trust_anchors",
                    "db_trust_sources_collection": "trust_sources",
                    "data_ttl": 63072000
                },
                "connection_params": {
                    "username": "user",
                    "password": "psw"
                }
            }
        }
    },
    "metadata_jwks": [
        {
            "kty": "EC",
            "d": "i0HQiqDPXf-MqC776ztbgOCI9-eARhcUczqJ-7_httc",
            "use": "sig",
            "crv": "P-256",
            "kid": "f10aca0992694b3581f6f699bfc8a2c6cc687725",
            "x": "jE2RpcQbFQxKpMqehahgZv6smmXD0i/LTP2QRzMADk4",
            "y": "qkMx5iqt5PhPu5tfctS6HsP+FmLgrxfrzUV2GwMQuh8",
            "alg": "ES256"
        }
    ],
    "credential_configurations": {
        "lookup_source":"openid4vci"
    }
}

MOCK_INTERNAL_ATTRIBUTES = {}
MOCK_BASE_URL = "example.com"
MOCK_NAME = "openid4vcimock"

INVALID_ATTESTATION_HEADERS = [
    {"OAuth-Client-Attestation": "", "OAuth-Client-Attestation-PoP": "valid"},
    {"OAuth-Client-Attestation": None, "OAuth-Client-Attestation-PoP": "valid"},
    {"OAuth-Client-Attestation-PoP": "valid"},
    {"OAuth-Client-Attestation": "valid", "OAuth-Client-Attestation-PoP": ""},
    {"OAuth-Client-Attestation": "valid", "OAuth-Client-Attestation-PoP": None},
    {"OAuth-Client-Attestation": "valid"},
    {"OAuth-Client-Attestation": "", "OAuth-Client-Attestation-PoP": ""},
    {"OAuth-Client-Attestation": None, "OAuth-Client-Attestation-PoP": None},
    {}
]

def get_mocked_openid4vpi_entity() -> OpenId4VCIEntity:
    return OpenId4VCIEntity(
        document_id = str(uuid.uuid4()),
        request_uri_part = "request_uri_part",
        state="xyz456",
        session_id="sessionid",
        remote_flow_typ=RemoteFlowType.SAME_DEVICE,
        client_id = "client123",
        code_challenge = "code_challenge",
        code_challenge_method = "S256",
        redirect_uri="https://client.com",
        authorization_details=[]
    )

def get_mocked_satosa_context(method ="POST", content_type = FORM_URLENCODED, headers=None) -> Context:
    if headers is None:
        headers = {
            HTTP_CONTENT_TYPE_HEADER: content_type,
            OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid-pop",
            OAUTH_CLIENT_ATTESTATION_HEADER: "valid"
        }
    context = Context()
    context.request_method = method
    context.http_headers = headers
    context.state = {
        "SESSION_ID": "sessionid"
    }
    return context

def get_pyeudiw_frontend_config_with_openid_credential_issuer(openid_credential_issuer = None):
    if openid_credential_issuer:
        config = copy.deepcopy(MOCK_PYEUDIW_FRONTEND_CONFIG)
        metadata = config.get("metadata", {})
        openid_issuer = metadata.get("openid_credential_issuer", {})
        openid_issuer["credential_issuer"] = openid_credential_issuer
        return config

    return MOCK_PYEUDIW_FRONTEND_CONFIG