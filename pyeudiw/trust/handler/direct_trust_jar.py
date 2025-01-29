import os

from pyeudiw.trust.handler._direct_trust_jwk import _DirectTrustJwkHandler


DEFAULT_JARISSUER_METADATA_ENDPOINT = "/.well-known/jar-issuer"
"""Default endpoint adopted by potential interopebility document as of version 1.1.
The endpopint should be positioned between the host component and the path component (if any) of the iss claim value in the JAR.
"""

DEFAULT_DIRECT_TRUST_JAR_HTTPC_PARAMS = {
    "connection": {
        "ssl": os.getenv("PYEUDIW_HTTPC_SSL", True)
    },
    "session": {
        "timeout": os.getenv("PYEUDIW_HTTPC_TIMEOUT", 6)
    }
}


class DirectTrustJar(_DirectTrustJwkHandler):
    """DirectTrustJar is specialization of _DirectTrustJwkHandler
    used in the context of JAR (RFC9101).
    """

    def __init__(
        self,
        httpc_params: dict = DEFAULT_DIRECT_TRUST_JAR_HTTPC_PARAMS,
        jwk_endpoint: str = DEFAULT_JARISSUER_METADATA_ENDPOINT,
        cache_ttl: int = 0,
        jwks: list[dict] | None = None
    ):
        super().__init__(
            httpc_params=httpc_params,
            jwk_endpoint=jwk_endpoint,
            cache_ttl=cache_ttl,
            jwks=jwks
        )
