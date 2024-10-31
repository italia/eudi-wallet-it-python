import os
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.vci.jwks_provider import RemoteVciJwksSource
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import get_http_url


DEAFAULT_JWK_ENDPOINT = "/.well-known/jwt-vc-issuer"
DEAFAULT_METADATA_ENDPOINT = "/.well-known/openid-credential-issuer"

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

class DirectTrustJWTHandler(TrustHandlerInterface, BaseLogger):
    def __init__(
            self, 
            httpc_params: dict = DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS, 
            jwk_endpoint: str = DEAFAULT_JWK_ENDPOINT,
            metadata_endpoint: str = DEAFAULT_METADATA_ENDPOINT
        ) -> None:
        self.httpc_params = httpc_params
        self.jwk_endpoint = jwk_endpoint
        self.metadata_endpoint = metadata_endpoint
        
    def extract(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        try:
            self.get_metadata(issuer, trust_source)
            jwk_source = RemoteVciJwksSource(self.httpc_params, self.jwk_endpoint)
            jwks = jwk_source.get_jwks(issuer)
            trust_source.add_keys(jwks)
            return trust_source
        except Exception as e:
            self._log_warning("JWK Extraction", f"error fetching JWK from {issuer}: {e}")
            return trust_source

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        issuer_normalized = issuer if issuer[-1] != '/' else issuer[:-1]
        url = issuer_normalized + self.metadata_endpoint

        try:
            response = get_http_url(url, self.httpc_params)
            metadata = response[0].json()
            trust_source.metadata = metadata
            return trust_source
        except Exception as e:
            self._log_warning("Metadata Extraction", f"error fetching metadata from {url}: {e}")