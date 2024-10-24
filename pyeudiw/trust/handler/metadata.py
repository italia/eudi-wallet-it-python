import os
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.tools.utils import get_http_url
from pyeudiw.trust.handler.interface import TrustHandlerInterface

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

class MetadataHandler(TrustHandlerInterface, BaseLogger):
    @staticmethod
    def extract(
        self, 
        issuer: str, 
        trust_source: TrustSourceData, 
        data_endpoint: str = DEAFAULT_METADATA_ENDPOINT,
        httpc_params: dict = {}
    ) -> TrustSourceData:
        issuer_normalized = [issuer if issuer[-1] != '/' else issuer[:-1]]
        url = issuer_normalized + data_endpoint

        try:
            response = get_http_url(url, httpc_params)
            metadata = response[0].json()
            trust_source.metadata = metadata
            return trust_source
        except Exception as e:
            self._log_warning("Metadata Extraction", f"error fetching metadata from {url}: {e}")
            return trust_source
        
    @staticmethod
    def name() -> str:
        return "MetadataExtractor"