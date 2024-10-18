import os

from pyeudiw.trust.default.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.trust.interface import TrustEvaluator


DEFAULT_DIRECT_TRUST_PARAMS = {
    "httpc_params": {
        "connection": {
            "ssl": os.getenv("PYEUDIW_HTTPC_SSL", True)
        },
        "session": {
            "timeout": os.getenv("PYEUDIW_HTTPC_TIMEOUT", 6)
        }
    }
}


def default_trust_evaluator() -> TrustEvaluator:
    return DirectTrustSdJwtVc(**DEFAULT_DIRECT_TRUST_PARAMS)
