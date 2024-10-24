import os
from typing import Literal, Optional
from urllib.parse import ParseResult, urlparse

from pyeudiw.tools.utils import cacheable_get_http_url, get_http_url
from pyeudiw.trust.interface import TrustEvaluator

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


class InvalidJwkMetadataException(Exception):
    pass


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
        self.http_async_calls = False

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        Fetches the public key of the issuer by querying a given endpoint.
        Previous responses might or might not be cached based on the cache_ttl
        parameter.

        :returns: a list of jwk(s)
        """
        md = self._get_jwk_metadata(issuer)
        jwks = self._extract_jwks_from_jwk_metadata(md)
        jwk_l: list[dict] = jwks.get("keys", [])
        if not jwk_l:
            raise InvalidJwkMetadataException("unable to find jwks in issuer jwk metadata")
        return jwk_l

    def _get_jwk_metadata(self, issuer: str) -> dict:
        """
        call the jwk metadata endpoint and return the whole document
        """
        jwk_endpoint = DirectTrustSdJwtVc.build_issuer_jwk_endpoint(issuer, self.jwk_endpoint)
        if self.cache_ttl:
            resp = cacheable_get_http_url(self.cache_ttl, jwk_endpoint, self.httpc_params, http_async=self.http_async_calls)
        else:
            resp = get_http_url([jwk_endpoint], self.httpc_params, http_async=self.http_async_calls)[0]
        # TODO: check response status before returning json
        return resp.json()

    def _get_jwks_by_reference(self, jwks_reference_uri: str) -> dict:
        """
        call the jwks endpoint if jwks is defined by reference
        """
        if self.cache_ttl:
            resp = cacheable_get_http_url(self.cache_ttl, jwks_reference_uri, self.httpc_params, http_async=self.http_async_calls)
        else:
            resp = get_http_url([jwks_reference_uri], self.httpc_params, http_async=self.http_async_calls)[0]
        return resp.json()

    def _extract_jwks_from_jwk_metadata(self, md: dict) -> dict:
        """
        parse the jwk metadata document and return the jwks
        NOTE: jwks might be in the document by value or by reference
        """
        # TODO: unit test this function
        jwks: dict[Literal["keys"], list[dict]] | None = md.get("jwks", None)
        jwks_uri: str | None = md.get("jwks_uri", None)
        if (not jwks) and (not jwks_uri):
            raise InvalidJwkMetadataException("invalid issuing key metadata: missing both claims [jwks] and [jwks_uri]")
        if jwks:
            return jwks
        return self._get_jwks_by_reference(self, jwks_uri)

    def get_metadata(self, issuer: str) -> dict:
        """
        Fetches the public metadata of an issuer by interrogating a given
        endpoint. The endpoint must yield information in a format that
        can be transalted to a meaning dictionary (such as json)

        :returns: a dictionary of metadata information
        """
        if not issuer:
            raise ValueError("invalid issuer: cannot be empty value")
        url = DirectTrustSdJwtVc.build_issuer_metadata_endpoint(issuer, self.metadata_endpoint)
        if self.cache_ttl == 0:
            return get_http_url(url, self.httpc_params, self.http_async_calls)[0].json()
        return cacheable_get_http_url(self.cache_ttl, url, self.httpc_params, self.http_async_calls).json()

    def build_issuer_jwk_endpoint(issuer: str, well_known_path_component: str) -> str:
        # TODO: unit test this function
        baseurl = urlparse(issuer)
        well_known_path = well_known_path_component + baseurl.path
        well_known_url: str = ParseResult(baseurl.scheme, baseurl.netloc, well_known_path, baseurl.params, baseurl.query, baseurl.fragment).geturl()
        return well_known_url

    def build_issuer_metadata_endpoint(issuer: str, metadata_path_component: str) -> str:
        # TODO: unit test this function
        issuer_normalized = [issuer if issuer[-1] != '/' else issuer[:-1]]
        return issuer_normalized + metadata_path_component

    def __str__(self) -> str:
        return f"DirectTrustSdJwtVc(" \
            f"httpc_params={self.httpc_params}, " \
            f"cache_ttl={self.cache_ttl}, " \
            f"jwk_endpoint={self.jwk_endpoint}, " \
            f"metadata_endpoint={self.metadata_endpoint}" \
            ")"
