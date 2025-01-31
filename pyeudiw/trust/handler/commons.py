import os

DEFAULT_HTTPC_PARAMS = {
    "connection": {
        "ssl": os.getenv("PYEUDIW_HTTPC_SSL", True)
    },
    "session": {
        "timeout": os.getenv("PYEUDIW_HTTPC_TIMEOUT", 6)
    }
}

DEFAULT_OPENID4VCI_METADATA_ENDPOINT = "/.well-known/openid-credential-issuer"
"""Default endpoint where metadata issuer credential are exposed/
For further reference, see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-well-known-uri-registry
"""
