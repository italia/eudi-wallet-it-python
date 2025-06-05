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
    }
}