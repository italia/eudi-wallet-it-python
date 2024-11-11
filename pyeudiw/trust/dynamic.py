import logging
from typing import Optional
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.tools.utils import dynamic_class_loader
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust.exceptions import NoCriptographicMaterial

logger = logging.getLogger(__name__)

class CombinedTrustEvaluator(BaseLogger):
    """
    A trust evaluator that combines multiple trust models.
    """

    def __init__(self, handlers: list[TrustHandlerInterface], db_engine: DBEngine) -> None:
        """
        Initialize the CombinedTrustEvaluator.

        :param handlers: The trust handlers
        :type handlers: list[TrustHandlerInterface]
        :param db_engine: The database engine
        :type db_engine: DBEngine
        """
        self.db_engine: DBEngine = db_engine
        self.handlers: list[TrustHandlerInterface] = handlers
        self.handlers_names: list[str] = [e.name for e in self.handlers]
    
    def _retrieve_trust_source(self, issuer: str) -> Optional[TrustSourceData]:
        """
        Retrieve the trust source from the database.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: Optional[TrustSourceData]
        """
        try:
            trust_source = self.db_engine.get_trust_source(issuer)
            return TrustSourceData.from_dict(trust_source)
        except EntryNotFound:
            return None
    
    def _upsert_source_trust_materials(self, issuer: str, trust_source: Optional[TrustSourceData]) -> TrustSourceData:
        """
        Extract the trust material of a certain issuer from all the trust handlers.
        If the trust material is not found for a certain issuer the structure remain unchanged.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: Optional[TrustSourceData]
        """

        if not trust_source:
            trust_source = TrustSourceData.empty(issuer)

        for handler in self.handlers:
            trust_source = handler.extract_and_update_trust_materials(issuer, trust_source)
        
        self.db_engine.add_trust_source(trust_source.serialize())

        return trust_source
    
    def _get_trust_source(self, issuer: str) -> TrustSourceData:
        """
        Retrieve the trust source from the database or extract it from the trust handlers.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: TrustSourceData
        """
        trust_source = self._retrieve_trust_source(issuer)
        
        if not trust_source:
            trust_source = self._upsert_source_trust_materials(issuer, trust_source)

        return trust_source

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        Yields a list of public keys for an issuer, according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The public keys
        :rtype: list[dict]
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.keys:
            raise NoCriptographicMaterial(
                f"no trust evaluator can provide cyptographic material for {issuer}: searched among: {self.handlers_names}"
            )

        return trust_source.public_keys

    def get_metadata(self, issuer: str) -> dict:
        """
        Yields a dictionary of metadata about an issuer, according to some trust model.
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.metadata:
            raise Exception(f"no trust evaluator can provide metadata for {issuer}: searched among: {self.handlers_names}")

        return trust_source.metadata

    def is_revoked(self, issuer: str) -> bool:
        """
        Yield if the trust toward the issuer was revoked according to some trust model;
        This asusmed that  the isser exists, is valid, but is not trusted.

        :param issuer: The issuer
        :type issuer: str

        :returns: If the trust toward the issuer was revoked
        :rtype: bool
        """
        trust_source = self._get_trust_source(issuer)
        return trust_source.is_revoked

    def get_policies(self, issuer: str) -> dict[str, any]:
        """
        Get the policies of a certain issuer according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The policies
        :rtype: dict[str, any]
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.policies:
            raise Exception(f"no trust evaluator can provide policies for {issuer}: searched among: {self.handlers_names}")
        
        return trust_source.policies
    
    def get_selfissued_jwt_header_trust_parameters(self, issuer: str) -> list[dict]:
        """
        Get the trust parameters of a certain issuer according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust parameters
        :rtype: list[dict]
        """
        trust_source = self._get_trust_source(issuer)

        if not trust_source.trust_params:
            raise Exception(f"no trust evaluator can provide trust parameters for {issuer}: searched among: {self.handlers_names}")
        
        return {type: param.trust_params for type, param in trust_source.trust_params.items()}
    
    @staticmethod
    def from_config(config: dict, db_engine: DBEngine) -> 'CombinedTrustEvaluator':
        """
        Create a CombinedTrustEvaluator from a configuration.

        :param config: The configuration
        :type config: dict
        :param db_engine: The database engine
        :type db_engine: DBEngine
        
        :returns: The CombinedTrustEvaluator
        :rtype: CombinedTrustEvaluator
        """
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
        
