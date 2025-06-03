MOCK_PYEUDIW_FRONTEND_CONFIG = {
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
                    "PDA1Credential" :{
                        "id": "eudiw.pda1.se"
                    },
                    "EHICCredential":{
                        "id": "eudiw.ehic.se"
                    }
                },
                "authorization_servers": [],
                "credential_issuer":"",
            }
        }
    }