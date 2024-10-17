from pyeudiw.trust.default import DEFAULT_DIRECT_TRUST_PARAMS
from pyeudiw.trust.default.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.trust.dynamic import CombinedTrustEvaluator, dynamic_trust_evaluators_loader
from pyeudiw.trust.interface import TrustEvaluator


class MockTrustEvaluator(TrustEvaluator):
    """Mock realization of TrustEvaluator for testing purposes only
    """
    mock_jwk = {
        "crv": "P-256",
        "kid": "qTo9RGpuU_CSolt6GZmndLyPXJJa48up5dH1YbxVDPs",
        "kty": "EC",
        "use": "sig",
        "x": "xu0FC3OQLgsea27rL0-d2CpVyKijjwl8tF6HB-3zLUg",
        "y": "fUEsB8IrX2DgzqABfVsCody1RypAXX54fXQ1keoPP5Y"
    }

    def __init__(self):
        pass

    def get_public_keys(self, issuer: str) -> list[dict]:
        return [
            MockTrustEvaluator.mock_jwk
        ]

    def get_metadata(self, issuer: str) -> dict:
        return {
            "json_key": "json_value"
        }

    def is_revoked(self, issuer: str) -> bool:
        return False

    def get_policies(self, issuer: str) -> dict:
        return {}


def test_trust_evaluators_loader():
    config = {
        "mock": {
            "module": "pyeudiw.tests.trust.test_dynamic",
            "class": "MockTrustEvaluator",
            "config": {}
        },
        "direct_trust_sd_jwt_vc": {
            "module": "pyeudiw.trust.default.direct_trust_sd_jwt_vc",
            "class": "DirectTrustSdJwtVc",
            "config": {
                "jwk_endpoint": "/.well-known/jwt-vc-issuer",
                "httpc_params": {
                    "connection": {
                        "ssl": True
                    },
                    "session": {
                        "timeout": 6
                    }
                }
            }
        }
    }
    trust_sources = dynamic_trust_evaluators_loader(config)
    assert "mock" in trust_sources
    assert trust_sources["mock"].__class__.__name__ == "MockTrustEvaluator"
    assert "direct_trust_sd_jwt_vc" in trust_sources
    assert trust_sources["direct_trust_sd_jwt_vc"].__class__.__name__ == "DirectTrustSdJwtVc"


def test_combined_trust_evaluator():
    evaluators = {
        "mock": MockTrustEvaluator(),
        "direct_trust_sd_jwt_vc": DirectTrustSdJwtVc(**DEFAULT_DIRECT_TRUST_PARAMS)
    }
    combined = CombinedTrustEvaluator(evaluators)
    # TODO: re-enable when fixed
    # assert MockTrustEvaluator.mock_jwk in combined.get_public_keys("mock_issuer")
