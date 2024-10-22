from pyeudiw.trust.default.direct_trust_sd_jwt_vc import DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS, DirectTrustSdJwtVc
from pyeudiw.trust.interface import TrustEvaluator


def default_trust_evaluator() -> TrustEvaluator:
    return DirectTrustSdJwtVc(**DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS)
