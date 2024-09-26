import importlib
from typing import TypedDict

from pyeudiw.trust.default.direct_trust import DirectTrustSdJwtVc
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.trust.interface import TrustEvaluator
from pyeudiw.trust._log import _package_logger


_DynamicTrustConfiguration = TypedDict("_DynamicTrustConfiguration", {"module": str, "class": str, "config": dict})


DEFAULT_HTTPC_PARAMS = {
    "connection": {
        "ssl": True
    },
    "session": {
        "timeout": 6
    }
}


def trust_evaluators_loader(trust_config: dict[str, _DynamicTrustConfiguration]) -> dict[str, TrustEvaluator]:
    """
    Load a dynamically importable/configurable set of TrustEvaluators, 
    identified by the trust model they refer to.
    """
    trust_instances: dict[str, TrustEvaluator] = {}
    if not trust_config:
        _package_logger.warning("no configured trust model, using direct trust model")
        trust_instances["direct_trust"] = DirectTrustSdJwtVc(DEFAULT_HTTPC_PARAMS)
    for trust_model_name, module_config in trust_config.items():
        try:
            module = importlib.import_module(module_config["module"])
            class_type: type[TrustEvaluator] = getattr(module, module_config["class"])
            class_config: dict = module_config["config"]
        except Exception as e:
            raise TrustConfigurationError(f"invalid configuration for {trust_model_name}: {e}", e)
        trust_instances[trust_model_name] = class_type(**class_config)
    return trust_instances
