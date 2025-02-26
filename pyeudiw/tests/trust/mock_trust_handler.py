from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.trust.model.trust_source import TrustParameterData
from datetime import datetime
from typing import Union

mock_jwk = {
    "crv": "P-256",
    "kid": "qTo9RGpuU_CSolt6GZmndLyPXJJa48up5dH1YbxVDPs",
    "kty": "EC",
    "use": "sig",
    "x": "xu0FC3OQLgsea27rL0-d2CpVyKijjwl8tF6HB-3zLUg",
    "y": "fUEsB8IrX2DgzqABfVsCody1RypAXX54fXQ1keoPP5Y",
}


class MockTrustHandler(TrustHandlerInterface):
    """
    Mock realization of TrustEvaluator for testing purposes only
    """

    def __init__(self, *args, **kwargs):
        self.client_id = kwargs.get("default_client_id", None)

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> dict:
        if issuer == self.default_client_id:
            trust_source.metadata = {"default_key": "default_value"}
            return trust_source

        trust_source.metadata = {"json_key": "json_value"}
        return trust_source

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        trust_source = self.get_metadata(issuer, trust_source)
        trust_source.keys.append(mock_jwk)

        if issuer == self.default_client_id:
            trust_param = TrustParameterData(
                type="trust_param_type",
                trust_params= {"default_trust_param_key": "default_trust_param_value"},
                expiration_date=datetime.now(),
            )
        else:
            trust_param = TrustParameterData(
                type="trust_param_type",
                trust_params= {"trust_param_key": "trust_param_value"},
                expiration_date=datetime.now(),
            )

        trust_source.add_trust_param("trust_param", trust_param)

        return trust_source


class NonConformatTrustHandler:
    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> dict:
        return trust_source

    def extract(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        return trust_source
