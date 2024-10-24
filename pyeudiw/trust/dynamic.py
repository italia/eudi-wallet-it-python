import sys
from typing import Optional

if float(f"{sys.version_info.major}.{sys.version_info.minor}") >= 3.12:
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.trust.default import default_trust_evaluator
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.trust.interface import TrustEvaluator
from pyeudiw.trust._log import _package_logger
from pyeudiw.tools.utils import dynamic_class_loader, satisfy_interface
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData


TrustModuleConfiguration_T = TypedDict("_DynamicTrustConfiguration", {"module": str, "class": str, "config": dict})


def dynamic_trust_evaluators_loader(trust_config: dict[str, TrustModuleConfiguration_T]) -> dict[str, TrustEvaluator]: # type: ignore
    """Load a dynamically importable/configurable set of TrustEvaluators,
    identified by the trust model they refer to.
    If not configurations a re given, a default is returned instead
    implementation of TrustEvaluator is returned instead.

    :return: a dictionary where the keys are common name identifiers
        for the trust mechanism ,a nd the keys are acqual class instances that satisfy
        the TrustEvaluator interface
    :rtype: dict[str, TrustEvaluator]
    """
    trust_instances: dict[str, TrustEvaluator] = {}
    if not trust_config:
        _package_logger.warning("no configured trust model, using direct trust model")
        trust_instances["direct_trust_sd_jwt_vc"] = default_trust_evaluator()
        return trust_instances

    for trust_model_name, trust_module_config in trust_config.items():
        try:
            trust_evaluator_instance = dynamic_class_loader(trust_module_config["module"], trust_module_config["class"], trust_module_config["config"])
        except Exception as e:
            raise TrustConfigurationError(f"invalid configuration for {trust_model_name}: {e}", e)
        
        if not satisfy_interface(trust_evaluator_instance, TrustEvaluator):
            raise TrustConfigurationError(f"class {trust_evaluator_instance.__class__} does not satisfy the interface TrustEvaluator")
        
        trust_instances[trust_model_name] = trust_evaluator_instance
    return trust_instances


class CombinedTrustEvaluator(TrustEvaluator, BaseLogger):
    def __init__(
            self, 
            db_engine: DBEngine,
            extracors: list[TrustHandlerInterface]
        ) -> None:
        self.db_engine: DBEngine = db_engine
        self.extractors: list[TrustHandlerInterface] = extracors
        self.extractors_names: list[str] = [e.name() for e in self.extractors]
    
    def _retrieve_trust_source(self, issuer: str) -> Optional[TrustSourceData]:
        trust_source = self.db_engine.get_trust_source(issuer)
        if trust_source:
            return TrustSourceData.from_dict(trust_source)
        return  None
    
    def _extract_trust_source(self, issuer: str) -> Optional[TrustSourceData]:
        trust_source = TrustSourceData.empty()

        for extractor in self.extractors:
            trust_source: TrustSourceData = extractor.extract(issuer, trust_source)
        
        self.db_engine.add_trust_source(issuer, trust_source.serialize())

        return trust_source
    
    def _get_trust_source(self, issuer: str) -> TrustSourceData:
        trust_source = self._retrieve_trust_source(issuer)
        if not trust_source:
            trust_source = self._extract_trust_source(issuer)
        return trust_source

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        yields the public cryptographic material of the issuer

        :returns: a list of jwk(s); note that those key are _not_ necessarely
            identified by a kid claim
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.keys:
            raise Exception(f"no trust evaluator can provide cyptographic material for {issuer}: searched among: {self.extractors_names}")

        return trust_source.public_keys

    def get_metadata(self, issuer: str) -> dict:
        """
        yields a dictionary of metadata about an issuer, according to some
        trust model.
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.metadata:
            raise Exception(f"no trust evaluator can provide metadata for {issuer}: searched among: {self.extractors_names}")

        return trust_source.metadata

    def is_revoked(self, issuer: str) -> bool:
        """
        yield if the trust toward the issuer was revoked according to some trust model;
        this asusmed that  the isser exists, is valid, but is not trusted.
        """
        trust_source = self._get_trust_source(issuer)
        return trust_source.is_revoked

    def get_policies(self, issuer: str) -> dict:
        trust_source = self._get_trust_source(issuer)

        if not trust_source.policies:
            raise Exception(f"no trust evaluator can provide policies for {issuer}: searched among: {self.extractors_names}")
        
        return trust_source.policies
    
    def get_selfissued_jwt_header_trust_parameters(self, issuer: str) -> dict:
        trust_source = self._get_trust_source(issuer)

        if not trust_source.trust_params:
            raise Exception(f"no trust evaluator can provide trust parameters for {issuer}: searched among: {self.extractors_names}")
        
        return trust_source.trust_params
        
