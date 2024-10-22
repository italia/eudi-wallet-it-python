import os
import time
from typing import Optional

from pyeudiw.tools.utils import get_http_url
from pyeudiw.trust.interface import TrustEvaluator
from pyeudiw.vci.jwks_provider import CachedVciJwksSource, RemoteVciJwksSource, VciJwksSource
from pyeudiw.vci.utils import cacheable_get_http_url


DEFAULT_ISSUER_JWK_ENDPOINT = "/.well-known/jwt-vc-issuer"
DEFAULT_METADATA_ENDPOINT = "/.well-known/openid-credential-issuer"
DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS = {
    "httpc_params": {
        "connection": {
            "ssl": os.getenv("PYEUDIW_HTTPC_SSL", True)
        },
        "session": {
            "timeout": os.getenv("PYEUDIW_HTTPC_TIMEOUT", 6)
        }
    }
}


class DirectTrust(TrustEvaluator):
    pass


class DirectTrustSdJwtVc(DirectTrust):
    """
    DirectTrust trust models assumes that an issuer is always trusted, in the sense
    that no trust verification actually happens. The issuer is assumed to be an URI
    and its keys and metadata information are publicly exposed on the web.
    Such keys/metadata can always be fetched remotely and long as the issuer is
    available.
    """
    def __init__(self, httpc_params: Optional[dict] = None, cache_ttl: int = 0, jwk_endpoint: str = DEFAULT_ISSUER_JWK_ENDPOINT,
                 metadata_endpoint: str = DEFAULT_METADATA_ENDPOINT):
        if httpc_params is None:
            self.httpc_params = DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS["httpc_params"]
        self.httpc_params = httpc_params
        self.cache_ttl = cache_ttl
        self.jwk_endpoint = jwk_endpoint
        self.metadata_endpoint = metadata_endpoint
        self._vci_jwks_source: VciJwksSource = None
        if self.cache_ttl == 0:
            self._vci_jwks_source = RemoteVciJwksSource(httpc_params, jwk_endpoint)
        else:
            self._vci_jwks_source = CachedVciJwksSource(self.cache_ttl, httpc_params, jwk_endpoint)

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        Fetches the public key of the issuer by querying a given endpoint.
        Previous responses might or might not be cached based on the cache_ttl
        parameter.

        :returns: a list of jwk(s)
        """
        return self._vci_jwks_source.get_jwks(issuer)

    def get_metadata(self, issuer: str) -> dict:
        """
        Fetches the public metadata of an issuer by interrogating a given
        endpoint. The endpoint must yield information in a format that
        can be transalted to a meaning dictionary (such as json)

        :returns: a dictionary of metadata information
        """
        if not issuer:
            raise ValueError("invalid issuer: cannot be empty value")
        issuer_normalized = [issuer if issuer[-1] != '/' else issuer[:-1]]
        url = issuer_normalized + self.metadata_endpoint
        if self.cache_ttl == 0:
            return get_http_url(url, self.httpc_params)[0].json()
        ttl_timestamp = round(time.time() / self.cache_ttl)
        return cacheable_get_http_url(ttl_timestamp, url, self.httpc_params)[0].json()

    def __str__(self) -> str:
        return f"DirectTrustSdJwtVc(" \
            f"httpc_params={self.httpc_params}, " \
            f"cache_ttl={self.cache_ttl}, " \
            f"jwk_endpoint={self.jwk_endpoint}, " \
            f"metadata_endpoint={self.metadata_endpoint}" \
            ")"
