from pyeudiw.trust.model.trust_source import TrustSourceData

class TrustHandlerInterface:
    @staticmethod
    def extract(
        self, 
        issuer: str, 
        trust_source: TrustSourceData, 
        data_endpoint: str,
        httpc_params: dict
    ) -> TrustSourceData:
        NotImplementedError

    @staticmethod
    def verify() -> bool:
        NotImplementedError

    @staticmethod
    def name() -> str:
        NotImplementedError