import os
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import get_http_url
from urllib.parse import ParseResult, urlparse
from typing import Literal
from pyeudiw.tools.utils import cacheable_get_http_url, get_http_url
from pyeudiw.trust.handler.exception import InvalidJwkMetadataException


DEAFAULT_JWK_ENDPOINT = "/.well-known/jwt-vc-issuer"
DEAFAULT_METADATA_ENDPOINT = "/.well-known/openid-credential-issuer"

DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS = {
    "connection": {
        "ssl": os.getenv("PYEUDIW_HTTPC_SSL", True)
    },
    "session": {
        "timeout": os.getenv("PYEUDIW_HTTPC_TIMEOUT", 6)
    }
}

class DirectTrustSdJwtVc(TrustHandlerInterface, BaseLogger):
    def __init__(
            self, 
            httpc_params: dict = DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS, 
            jwk_endpoint: str = DEAFAULT_JWK_ENDPOINT,
            metadata_endpoint: str = DEAFAULT_METADATA_ENDPOINT,
            cache_ttl: int = 0,
        ) -> None:
        self.httpc_params = httpc_params
        self.jwk_endpoint = jwk_endpoint
        self.metadata_endpoint = metadata_endpoint
        self.cache_ttl = cache_ttl
        self.http_async_calls = False

    def _get_jwk_metadata(self, issuer: str) -> dict:
        """
        call the jwk metadata endpoint and return the whole document
        """
        jwk_endpoint = DirectTrustSdJwtVc.build_issuer_jwk_endpoint(issuer, self.jwk_endpoint)
        if self.cache_ttl:
            resp = cacheable_get_http_url(self.cache_ttl, jwk_endpoint, self.httpc_params, http_async=self.http_async_calls)
        else:
            resp = get_http_url([jwk_endpoint], self.httpc_params, http_async=self.http_async_calls)[0]
        if (not resp) or (resp.status_code != 200):
            raise InvalidJwkMetadataException(f"failed to fetch valid jwk metadata: obtained {resp}")
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

    def _extract_jwks_from_jwk_metadata(self, metadata: dict) -> dict:
        """
        parse the jwk metadata document and return the jwks
        NOTE: jwks might be in the document by value or by reference
        """
        jwks: dict[Literal["keys"], list[dict]] | None = metadata.get("jwks", None)
        jwks_uri: str | None = metadata.get("jwks_uri", None)
        if (not jwks) and (not jwks_uri):
            raise InvalidJwkMetadataException("invalid issuing key metadata: missing both claims [jwks] and [jwks_uri]")
        if jwks:
            # get jwks by value
            return jwks
        return self._get_jwks_by_reference(jwks_uri)

    def build_issuer_jwk_endpoint(issuer_id: str, well_known_path_component: str) -> str:
        baseurl = urlparse(issuer_id)
        well_known_path = well_known_path_component + baseurl.path
        well_known_url: str = ParseResult(baseurl.scheme, baseurl.netloc, well_known_path, baseurl.params, baseurl.query, baseurl.fragment).geturl()
        return well_known_url

    def build_issuer_metadata_endpoint(issuer: str, metadata_path_component: str) -> str:
        issuer_normalized = issuer if issuer[-1] != '/' else issuer[:-1]
        return issuer_normalized + metadata_path_component
    
        
    def extract_and_update_trust_materials(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        """
        Fetches the public key of the issuer by querying a given endpoint.
        Previous responses might or might not be cached based on the cache_ttl
        parameter.

        :returns: a list of jwk(s)
        """
        if not issuer:
            raise ValueError("invalid issuer: cannot be empty value")
        
        try:
            self.get_metadata(issuer, trust_source)

            md = self._get_jwk_metadata(issuer)
            if not issuer == (obt_issuer := md.get("issuer", None)):
                raise InvalidJwkMetadataException(f"invalid jwk metadata: obtained issuer :{obt_issuer}, expected issuer: {issuer}")
            jwks = self._extract_jwks_from_jwk_metadata(md)
            jwk_l: list[dict] = jwks.get("keys", [])
            if not jwk_l:
                raise InvalidJwkMetadataException("unable to find jwks in issuer jwk metadata")
            
            trust_source.add_keys(jwk_l)
        except Exception as e:
            self._log_warning("Extracting JWK" ,f"Failed to extract jwks from issuer {issuer}: {e}")
    
        return trust_source

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        """
        Fetches the public metadata of an issuer by interrogating a given
        endpoint. The endpoint must yield information in a format that
        can be transalted to a meaning dictionary (such as json)

        :returns: a dictionary of metadata information
        """
        url = DirectTrustSdJwtVc.build_issuer_metadata_endpoint(issuer, self.metadata_endpoint)

        if self.cache_ttl == 0:
            trust_source.metadata = get_http_url(url, self.httpc_params, self.http_async_calls)[0].json()
        else:
            trust_source.metadata = cacheable_get_http_url(self.cache_ttl, url, self.httpc_params, self.http_async_calls).json()

        return trust_source