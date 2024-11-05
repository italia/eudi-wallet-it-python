from pyeudiw.trust.model.trust_source import TrustSourceData

class TrustHandlerInterface:
    def extract(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        return trust_source

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        return trust_source
    
    def verify() -> bool:
        NotImplementedError

    @property
    def name(self) -> str:
        return self.__class__.__name__