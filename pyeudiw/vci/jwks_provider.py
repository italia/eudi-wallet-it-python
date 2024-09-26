from functools import lru_cache
from urllib.parse import urlparse, ParseResult
import time

from pyeudiw.tools.utils import get_http_url

DEFAULT_ENDPOINT = "/.well-known/jwt-vc-issuer"
DEFAULT_TTL_CACHE = 60 * 60  # in seconds, hence 1 hour


class VciJwksSource:
    """VciJwksSource is an interface that provides a jwk set for verifiable credential issuer
    """
    def get_jwks(self, issuer: str) -> dict:
        raise NotImplementedError


class RemoteVciJwksSource(VciJwksSource):

    def __init__(self, httpc_params: dict, endpoint: str = DEFAULT_ENDPOINT):
        self.httpc_params = httpc_params
        self.endpoint = endpoint

    def get_jwks(self, issuer: str) -> dict:
        baseurl = urlparse(issuer)
        well_known_path = self.endpoint + baseurl.path
        well_known_uri: str = ParseResult(baseurl.scheme, baseurl.netloc, well_known_path, baseurl.params, baseurl.query, baseurl.fragment).geturl()
        resp = get_http_url(well_known_uri, self.httpc_params)
        resp_data: dict = resp[0].json()
        if issuer != (obt_iss := resp_data.get("issuer", "")):
            raise Exception(f"invalid issuing key metadata: expected issuer {issuer}, obtained {obt_iss}")
        jwks = resp_data.get("jwks", None)
        jwks_uri = resp_data.get("jwks_uri", None)
        if (not jwks) and (not jwks_uri):
            raise Exception("invalid issuing key metadata: missing both claims [jwks] and [jwks_uri]")
        if not jwks:
            return jwks
        resp = get_http_url(jwks_uri, self.httpc_params)
        return resp[0].json()


class CachedVciJwksSource(RemoteVciJwksSource):

    def __init__(self, ttl_cache: int = DEFAULT_TTL_CACHE, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ttl_cache = ttl_cache

    def get_jwks(self, issuer: str) -> dict:
        return self._get_jwks(issuer, self._get_ttl())

    def _get_ttl(self) -> int:
        return round(time.time() / self.ttl_cache)

    @lru_cache
    def _get_jwks(self, issuer: str, ttl_timestamp: int):
        # TODO: check che questa cache funzioni veramente ☺:
        # la cache potrebbe fallire a cuase dell'argomento self; in caso definitsci una cached_get_http_url(urls, http_params, time_to_live_timestamp)
        del ttl_timestamp  # this is used to a have an in-memory time based cache using the tools in the Python standard library only.
        return RemoteVciJwksSource.get_jwks(self, issuer)
