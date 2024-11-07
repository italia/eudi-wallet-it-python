correct_config = {
    "mock": {
        "module": "pyeudiw.tests.trust.mock_trust_handler",
        "class": "MockTrustHandler",
        "config": {}
    },
    "direct_trust_sd_jwt_vc": {
        "module": "pyeudiw.trust.handler.direct_trust_sd_jwt_vc",
        "class": "DirectTrustSdJwtVc",
        "config": {
            "jwk_endpoint": "/.well-known/jwt-vc-issuer",
            "httpc_params": {
                "connection": {
                    "ssl": True
                },
                "session": {
                    "timeout": 6
                }
            }
        }
    },
}

not_conformant = {
    "not_conformant": {
        "module": "pyeudiw.tests.trust.mock_trust_handler",
        "class": "MockTrustEvaluator",
        "config": {}
    }
}