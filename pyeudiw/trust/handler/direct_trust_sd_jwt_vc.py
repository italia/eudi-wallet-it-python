import os
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.vci.jwks_provider import RemoteVciJwksSource
from pyeudiw.tools.base_logger import BaseLogger


DEAFAULT_JWK_ENDPOINT = "/.well-known/jwt-vc-issuer"

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
    @staticmethod
    def extract(
            self, 
            issuer: str, 
            trust_source: TrustSourceData,
            data_endpoint: str = DEAFAULT_JWK_ENDPOINT,
            httpc_params: dict = {}
        ) -> TrustSourceData:

        try:
            jwk_source = RemoteVciJwksSource(httpc_params, data_endpoint)
            jwks = jwk_source.get_jwks(issuer)
            trust_source.add_keys(jwks)
            return trust_source
        except Exception as e:
            self._log_warning("JWK Extraction", f"error fetching JWK from {issuer}: {e}")
            return trust_source
    
    @staticmethod
    def name() -> str:
        return "DirectTrustJWTExtractor"