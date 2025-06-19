import copy
import json
import uuid

from cryptojwt import JWS
from cryptojwt.jwk.ec import new_ec_key
from satosa.context import Context

from pyeudiw.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.satosa.utils.validation import OAUTH_CLIENT_ATTESTATION_POP_HEADER, OAUTH_CLIENT_ATTESTATION_HEADER
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, FORM_URLENCODED

MOCK_METADATA_JWKS_CONFIG = [
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
]

MOCK_USER_STORAGE_CONFIG = {
    "storage": {
        "module": "pyeudiw.storage.user_storage",
        "class": "UserStorage",
        "init_params": {
            "url": "mongodb://satosa-mongo:27017",
            "conf": {
                "db_name": "eid_user",
                "db_users_collection": "users",
                "data_ttl": 63072000
            },
            "connection_params": {
                "username": "user",
                "password": "psw"
            }
        }
    }
}

MOCK_ENDPOINTS_CONFIG = {
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
    },
    "metadata_endpoint": {
        "module": "pyeudiw.openid4vci.endpoints.metadata_endpoint",
        "class": "MetadataHandler",
        "path": "/.well-known/openid-federation"
    }
}

MOCK_CREDENTIAL_CONFIGURATIONS = {
    "lookup_source": "openid4vci",
    "entity_default_sig_alg": "ES256",
    "credential_specification": {
        "dc_sd_jwt_mDL": {
            "template": """
                holder_disclosed_claims:
                    !sd given_name: "{{name}}"
                    !sd family_name: "{{surname}}"
                    !sd place_of_birth:
                        country: "{{countyOfBirth}}"
                        locality: "{{placeOfBirth}}"
                key_binding: true
                user_claims:
                    !sd birthdate: "{{dateOfBirth}}"
                    !sd family_name: "{{surname}}"
                    !sd given_name: "{{name}}"
                    !sd place_of_birth:
                        country: "{{countyOfBirth}}"
                        locality: "{{placeOfBirth}}"
                    !sd tax_id_code: "TINIT-{{fiscal_code}}"
                    !sd unique_id: "{{unique_id}}"
            """
        },
        "mso_mdoc_mDL": {
            "template": """
                holder_disclosed_claims:
                    !sd given_name: "{{name}}"
                    !sd family_name: "{{surname}}"
                    !sd place_of_birth:
                        country: "{{countyOfBirth}}"
                        locality: "{{placeOfBirth}}"
                key_binding: true
                user_claims:
                    !sd birthdate: "{{dateOfBirth}}"
                    !sd family_name: "{{surname}}"
                    !sd given_name: "{{name}}"
                    !sd place_of_birth:
                        country: "{{countyOfBirth}}"
                        locality: "{{placeOfBirth}}"
                    !sd tax_id_code: "TINIT-{{fiscal_code}}"
                    !sd unique_id: "{{unique_id}}"
            """
        }
    }
}

MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG = {
    "credential_configurations_supported": {
        "dc_sd_jwt_EuropeanDisabilityCard": {
            "format": "dc+sd-jwt",
            "scope": "EuropeanDisabilityCard"
        },
        "dc_sd_jwt_mDL": {
            "format": "dc+sd-jwt",
            "scope": "mDL",
            "cryptographic_binding_methods_supported": [
                "jwk"
            ]
        },
        "mso_mdoc_mDL": {
            "doctype": "org.iso.18013.5.1.mDL",
            "format": "mso_mdoc",
            "scope": "mDL",
            "cryptographic_binding_methods_supported": [
                "cose_key"
            ]
        }
    },
    "authorization_servers": [],
    "credential_issuer": "",
}

MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG = {
    "response_types_supported": ["code"],
    "response_modes_supported": [
        "form_post.jwt",
        "query"
    ],
    "code_challenge_methods_supported": ["S256"],
    "scopes_supported": ["scope1", "scope2", "openid"]
}

MOCK_JWT_CONFIG = {
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
}

MOCK_PYEUDIW_FRONTEND_CONFIG = {
    "endpoints": MOCK_ENDPOINTS_CONFIG,
    "jwt": MOCK_JWT_CONFIG,
    "metadata": {
        "oauth_authorization_server": MOCK_OAUTH_AUTHORIZATION_SERVER_CONFIG,
        "openid_credential_issuer": MOCK_OPENID_CREDENTIAL_ISSUER_CONFIG
    },
    "user_storage": MOCK_USER_STORAGE_CONFIG,
    "metadata_jwks": MOCK_METADATA_JWKS_CONFIG,
    "credential_configurations": MOCK_CREDENTIAL_CONFIGURATIONS,
    "trust": {
        "federation": {
            "config":{
                "entity_configuration_exp":600
            }
        }
    }
}

MOCK_INTERNAL_ATTRIBUTES = {
    "attributes": {
        "mail": {
            "openid4vci": ["mail", "email"]
        },
        "name": {
            "openid4vci": ["given_name"]
        },
        "surname": {
            "openid4vci": ["family_name"]
        },
        "placeOfBirth": {
            "openid4vci": ["placeOfBirth"]
        },
        "countyOfBirth": {
            "openid4vci": ["countyOfBirth"]
        },
        "dateOfBirth": {
            "openid4vci": ["dateOfBirth"]
        },
        "fiscal_code": {
            "openid4vci": ["fiscal_code", "fiscal_number", "personal_administrative_number"]
        }
    }
}

MOCK_BASE_URL = "example.com"
MOCK_NAME = "openid4vcimock"

INVALID_METHOD_FOR_POST_REQ =[
    "GET",
    "PUT",
    "DELETE",
    "PATCH"
]

INVALID_METHOD_FOR_GET_REQ =[
    "POST",
    "PUT",
    "DELETE",
    "PATCH"
]

INVALID_CONTENT_TYPES_NOT_FORM_URLENCODED = [
    "application/json",
    "application/xml",
    "application/pdf",
    "application/zip",
    "application/octet-stream",
    "application/x-pem-file",
    "application/jwt",
    "application/pkcs10",
    "application/pkcs7-mime",
    "application/ld+json",
    "application/vnd.api+json",
    "text/plain",
    "text/html",
    "text/css",
    "text/csv",
    "text/xml",
    "image/png",
    "image/jpeg",
    "image/svg+xml",
    "audio/mpeg",
    "video/mp4"
]

INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON = [
    "text/plain",
    "text/html",
    "text/css",
    "text/csv",
    "text/xml",
    "application/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/pdf",
    "application/zip",
    "application/octet-stream",
    "image/png",
    "image/jpeg",
    "image/svg+xml",
    "audio/mpeg",
    "video/mp4",
    "application/x-pem-file",
    "application/jwt",
    "application/pkcs10",
    "application/pkcs7-mime",
    "application/ld+json",
    "application/vnd.api+json"
]

INVALID_ATTESTATION_HEADERS = [
    {OAUTH_CLIENT_ATTESTATION_HEADER: "", OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid"},
    {OAUTH_CLIENT_ATTESTATION_HEADER: None, OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid"},
    {OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid"},
    {OAUTH_CLIENT_ATTESTATION_HEADER: "valid", OAUTH_CLIENT_ATTESTATION_POP_HEADER: ""},
    {OAUTH_CLIENT_ATTESTATION_HEADER: "valid", OAUTH_CLIENT_ATTESTATION_POP_HEADER: None},
    {OAUTH_CLIENT_ATTESTATION_HEADER: "valid"},
    {OAUTH_CLIENT_ATTESTATION_HEADER: "", OAUTH_CLIENT_ATTESTATION_POP_HEADER: ""},
    {OAUTH_CLIENT_ATTESTATION_HEADER: None, OAUTH_CLIENT_ATTESTATION_POP_HEADER: None},
    {}
]

def mock_valid_oauth_client_attestation_jwt(crv="P-256", use="sig", kid="ec1", alg="ES256"):
    ec_key = new_ec_key(crv=crv, use=use, kid=kid)
    payload = {"cnf": ec_key.serialize(private=False)}
    jws = JWS(json.dumps(payload), alg=alg)
    return jws.sign_compact([ec_key])

def get_mocked_openid4vpi_entity() -> OpenId4VCIEntity:
    return OpenId4VCIEntity(
        document_id = str(uuid.uuid4()),
        request_uri_part = "request_uri_part",
        state="xyz456",
        session_id="sessionid",
        remote_flow_typ=RemoteFlowType.SAME_DEVICE,
        client_id = "client123",
        code_challenge = "ef7a1e840dad06e97982b64f8575064303408f187af733444bc6eed9b543d043", # as sha256("code_verifier".encode('utf-8')).hexdigest()
        code_challenge_method = "S256",
        redirect_uri="https://client.com",
        authorization_details=[]
    )

def get_mocked_satosa_context(method="POST", content_type=FORM_URLENCODED, headers=None,
                              oauth_client_attestation_header=mock_valid_oauth_client_attestation_jwt()) -> Context:
    if headers is None:
        headers = {
                HTTP_CONTENT_TYPE_HEADER: content_type,
                OAUTH_CLIENT_ATTESTATION_POP_HEADER: "valid-pop",
                OAUTH_CLIENT_ATTESTATION_HEADER: oauth_client_attestation_header,
                "HTTP_USER_AGENT": "Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
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

REMOVE = object()  # special value for remove object
def mock_deserialized_overridable(base: dict, overrides=None):
    result = base.copy()
    if overrides:
        for k, v in overrides.items():
            if v is REMOVE:
                result.pop(k, None)  # remove key if exist
            else:
                result[k] = v
    return result