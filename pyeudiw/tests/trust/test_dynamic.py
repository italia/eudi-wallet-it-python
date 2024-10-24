from pyeudiw.trust.default import DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS
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
        },
        "federation": {
            "module": "pyeudiw.trust.default.federation",
            "class": "FederationTrustModel",
            "config": {
                "metadata_type": "wallet_relying_party",
                "authority_hints": [
                    "http://127.0.0.1:8000"
                ],
                "trust_anchors": [
                    {
                        "public_keys": []
                    },
                    "http://127.0.0.1:8000"
                ],
                "default_sig_alg": "RS256",
                "trust_marks": [],
                "federation_entity_metadata": {
                    "organization_name": "Developers Italia SATOSA OpenID4VP backend",
                    "homepage_uri": "https://developers.italia.it",
                    "policy_uri": "https://developers.italia.it",
                    "tos_uri": "https://developers.italia.it",
                    "logo_uri": "https://developers.italia.it/assets/icons/logo-it.svg"
                },
                "federation_jwks": [
                    {
                        "kty": "RSA",
                        "d": "QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7vtyCoA-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVGH9U3W_djh4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q",
                        "e": "AQAB",
                        "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
                        "n": "utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx6nq1uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBKwoxeRyD3zWE2FXRFBbhKGksMrCGnFDsNl5JTlPjaM3kYyImE941ggcuc495m-Fw",
                        "p": "2zmGXIMCEHPphw778YjVTar1eycih6fFSJ4I4bl1iq167GqO0PjlOx6CZ1-OdBTVU7HfrYRiUK_BnGRdPDn-DQghwwkB79ZdHWL14wXnpB5y-boHz_LxvjsEqXtuQYcIkidOGaMG68XNT1nM4F9a8UKFr5hHYT5_UIQSwsxlRQ0",
                        "q": "2jMFt2iFrdaYabdXuB4QMboVjPvbLA-IVb6_0hSG_-EueGBvgcBxdFGIZaG6kqHqlB7qMsSzdptU0vn6IgmCZnX-Hlt6c5X7JB_q91PZMLTO01pbZ2Bk58GloalCHnw_mjPh0YPviH5jGoWM5RHyl_HDDMI-UeLkzP7ImxGizrM"
                    }
                ]
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
        "direct_trust_sd_jwt_vc": DirectTrustSdJwtVc(**DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS)
    }
    combined = CombinedTrustEvaluator(evaluators)
    assert MockTrustEvaluator.mock_jwk in combined.get_public_keys("mock_issuer")
