import logging
from typing import Optional
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.trust.interface import TrustEvaluator
from pyeudiw.tools.utils import dynamic_class_loader
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust.exceptions import NoCriptographicMaterial

logger = logging.getLogger(__name__)

class CombinedTrustEvaluator(TrustEvaluator, BaseLogger):
    def __init__(self, handlers: list[TrustHandlerInterface], db_engine: DBEngine) -> None:
        self.db_engine: DBEngine = db_engine
        self.handlers: list[TrustHandlerInterface] = handlers
        self.handlers_names: list[str] = [e.name for e in self.handlers]
    
    def _retrieve_trust_source(self, issuer: str) -> Optional[TrustSourceData]:
        try:
            trust_source = self.db_engine.get_trust_source(issuer)
            return TrustSourceData.from_dict(trust_source)
        except EntryNotFound:
            return None
    
    def _extract_trust_source(self, issuer: str) -> Optional[TrustSourceData]:
        trust_source = TrustSourceData.empty(issuer)

        for extractor in self.handlers:
            trust_source = extractor.extract(issuer, trust_source)
        
        self.db_engine.add_trust_source(trust_source.serialize())

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
            trust_source = self._extract_trust_source(issuer)

        if not trust_source.keys:
            raise NoCriptographicMaterial(
                f"no trust evaluator can provide cyptographic material for {issuer}: searched among: {self.handlers_names}"
            )

        return trust_source.public_keys

    def get_metadata(self, issuer: str) -> dict:
        """
        yields a dictionary of metadata about an issuer, according to some
        trust model.
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.metadata:
            raise Exception(f"no trust evaluator can provide metadata for {issuer}: searched among: {self.handlers_names}")

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
            raise Exception(f"no trust evaluator can provide policies for {issuer}: searched among: {self.handlers_names}")
        
        return trust_source.policies
    
    def get_selfissued_jwt_header_trust_parameters(self, issuer: str) -> dict:
        trust_source = self._get_trust_source(issuer)

        if not trust_source.trust_params:
            raise Exception(f"no trust evaluator can provide trust parameters for {issuer}: searched among: {self.handlers_names}")
        
        return trust_source.trust_params
    
    @staticmethod
    def from_config(config: dict, db_engine: DBEngine) -> 'CombinedTrustEvaluator':
        handlers = []

        for handler_name, handler_config in config.items():
            try:
                trust_handler = dynamic_class_loader(
                    handler_config["module"], 
                    handler_config["class"], 
                    handler_config["config"]
                )
            except Exception as e:
                raise TrustConfigurationError(f"invalid configuration for {handler_name}: {e}", e)
            
            if not isinstance(trust_handler, TrustHandlerInterface):
                raise TrustConfigurationError(f"class {trust_handler.__class__} does not satisfy the interface TrustEvaluator")
            
            handlers.append(trust_handler)

        if not handlers:
            logger.warning("No configured trust model, using direct trust model")
            handlers.append(DirectTrustSdJwtVc())

        return CombinedTrustEvaluator(handlers, db_engine)
        
