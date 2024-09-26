import time

from pyeudiw.tools.utils import get_http_url
from pyeudiw.trust.interface import TrustEvaluator
from pyeudiw.vci.jwks_provider import CachedVciJwksSource, RemoteVciJwksSource, VciJwksSource
from pyeudiw.vci.utils import cacheable_get_http_url


DEFAULT_ISSUER_JWK_ENDPOINT = "/.well-known/jwt-vc-issuer"
DEFAULT_METADATA_ENDPOINT = "/.well-known/openid-credential-issuer"


class DirectTrust(TrustEvaluator):
    pass


class DirectTrustSdJwtVc(DirectTrust):

    def __init__(self, httpc_params: dict, cache_ttl: int = 0, jwk_endpoint: str = DEFAULT_ISSUER_JWK_ENDPOINT,
                 metadata_endpoint: str = DEFAULT_METADATA_ENDPOINT):
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
        yields the public cryptographic material of the issuer

        :returns: a list of jwk(s)
        """
        return self._vci_jwks_source.get_jwks(issuer)

    def get_metadata(self, issuer: str) -> dict:
        if not issuer:
            raise ValueError("invalid issuer: cannot be empty value")
        issuer_normalized = [issuer if issuer[-1] != '/' else issuer[:-1]]
        url = issuer_normalized + self.metadata_endpoint
        if self.cache_ttl == 0:
            return get_http_url(url, self.httpc_params)[0].json()
        ttl_timestamp = round(time.time() / self.cache_ttl)
        return cacheable_get_http_url(ttl_timestamp, url, self.httpc_params)[0].json()
