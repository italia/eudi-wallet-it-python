import logging
from typing import Any, Callable, Optional

import satosa.context
from cryptojwt.jwk.jwk import key_from_jwk_dict

from typing import Union, Literal
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import dynamic_class_loader
from pyeudiw.trust.exceptions import NoCriptographicMaterial, TrustConfigurationError, NoMetadata
from pyeudiw.trust.handler.direct_trust_jar import DirectTrustJar
from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData

logger = logging.getLogger(__name__)

UpsertMode = Union[Literal["update_first"], Literal["cache_first"]]

INCLUDE_JWT_HEADER_CONFIG_NAME = "include_issued_jwt_header_param"


class CombinedTrustEvaluator(BaseLogger):
    """
    A trust evaluator that combines multiple trust models.
    """

    def __init__(
        self, 
        handlers: list[TrustHandlerInterface], 
        db_engine: DBEngine,
        mode: UpsertMode = "update_first"
    ) -> None:
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
        self.mode = mode

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

            if trust_source:
                del trust_source["_id"]
                return TrustSourceData.from_dict(trust_source)

            return None
        except EntryNotFound:
            return None
        
    def _update_upsert_source_trust_materials(
        self, trust_source: Optional[TrustSourceData], issuer: Optional[str] = None
    ) -> TrustSourceData:
        """
        Extract the trust material of a certain issuer from all the trust handlers using the update_first mode.
        It always updates first the trust material of the issuer and, if it is not found, it extracts it from cache.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: Optional[TrustSourceData]
        """
        for handler in self.handlers:
            trust_source = handler.extract_and_update_trust_materials(
                issuer, trust_source
            )   

        self.db_engine.add_trust_source(trust_source.serialize())

        return trust_source

    def _cache_upsert_source_trust_materials(
        self, trust_source: Optional[TrustSourceData], issuer: Optional[str] = None
    ) -> TrustSourceData:
        """
        Extract the trust material of a certain issuer from all the trust handlers using the cache_first mode.
        It always extracts first the trust material of the issuer from cache and, if it is not found, it updates it.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: Optional[TrustSourceData]
        """
        for handler in self.handlers:
            handler_name = handler.__class__.__name__

            trust_param = trust_source.get_trust_evaluation_type_by_handler_name(handler_name)

            if not trust_param or trust_param.expired or trust_source.revoked:
                trust_source = handler.extract_and_update_trust_materials(
                    issuer, trust_source
                )

        self.db_engine.add_trust_source(trust_source.serialize())

        return trust_source

    def _upsert_source_trust_materials(
        self, trust_source: Optional[TrustSourceData], issuer: Optional[str] = None, force_update: bool = False
    ) -> TrustSourceData:
        """
        Extract the trust material of a certain issuer from all the trust handlers.
        If the trust material is not found for a certain issuer the structure remain unchanged.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: Optional[TrustSourceData]
        """

        entity_id = issuer or "__internal__"

        if not trust_source:
            trust_source = TrustSourceData.empty(entity_id)

        if entity_id == "__internal__":
            return self._cache_upsert_source_trust_materials(trust_source, issuer)
        
        if self.mode == "update_first" or force_update:
            return self._update_upsert_source_trust_materials(trust_source, issuer)
        else:
            return self._cache_upsert_source_trust_materials(trust_source, issuer)
    
    def _get_trust_source(self, issuer: Optional[str] = None, force_update: bool = False) -> TrustSourceData:
        """
        Retrieve the trust source from the database or extract it from the trust handlers.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust source
        :rtype: TrustSourceData
        """
        trust_source = self._retrieve_trust_source(issuer or "__internal__")            

        return self._upsert_source_trust_materials(trust_source, issuer, force_update)

    def get_public_keys(
            self, 
            issuer: Optional[str] = None, 
            static_trust_materials: dict = {}, 
            force_update: bool = False
        ) -> list[dict]:
        """
        Yields a list of public keys for an issuer, according to some trust model.
        If trust materials are provided, they are used to derive the public keys.
        If not, the public keys are derived from a trust model that does not require trust materials to attest the trust.

        :param issuer: The issuer
        :type issuer: str
        :param static_trust_materials: The static trust materials
        :type static_trust_materials: dict
        :param force_update: If the public keys should be updated even if they are already present in the cache
        :type force_update: bool

        :returns: The public keys
        :rtype: list[dict]
        """
        keys = []
        thumbprints = []
        used_handlers = []

        trust_source = self._get_trust_source(issuer, force_update)

        # try to derive the public key from static trust materials
        if static_trust_materials:
            for key, trust_material in static_trust_materials.items():
                for handler in self.handlers:
                    if handler.get_handled_trust_material_name() == key:
                        status, trust_source = handler.validate_trust_material(
                            trust_material, 
                            trust_source
                        )

                        if status:
                            self.db_engine.add_trust_source(trust_source.serialize())
                            evaluation_type = trust_source.get_trust_evaluation_type_by_handler_name(handler.__class__.__name__)
                            return [key_from_jwk_dict(jwk).serialize(private=False) for jwk in evaluation_type.jwks]
                        else:
                            used_handlers.append(handler.__class__.__name__)

            self._log_warning("static trust evaluation", f"no configured trust handler can successfully process static trust material {static_trust_materials} of issuer {issuer}")

        # try with handlers that don't use static trust materials like DirectTrustJar
        filetered_handlers = [handler for handler in self.handlers if handler.__class__.__name__ not in used_handlers]

        for handler in filetered_handlers:
            if (evaluation_type := trust_source.get_trust_evaluation_type_by_handler_name(handler.__class__.__name__)) is not None:
                for jwk in evaluation_type.jwks:
                    key = key_from_jwk_dict(jwk)
                    thumbprint = key.thumbprint("SHA-256")
                    if thumbprint not in thumbprints:
                        thumbprints.append(thumbprint)
                        keys.append(key.serialize(private=False))

        if not keys:
            raise NoCriptographicMaterial(
                f"no trust evaluator can provide cyptographic material "
                f"for {issuer}: searched among: {self.handlers_names}"
            )

        return keys

    def get_metadata(self, issuer: Optional[str] = None, force_update: bool = False) -> dict:
        """
        Yields a dictionary of metadata about an issuer, according to some trust model.

        :param issuer: The issuer
        :type issuer: str
        :param force_update: If the metadata should be updated even if it is already present in the cache
        :type force_update: bool

        :returns: The metadata
        :rtype: dict
        """
        trust_source = self._get_trust_source(issuer, force_update)

        if not trust_source.metadata:
            raise NoMetadata(
                f"no trust evaluator can provide metadata for {issuer}: "
                f"searched among: {self.handlers_names}"
            )
        
        metadata = trust_source.metadata.copy()
        
        if "jwks" in metadata and "keys" in metadata["jwks"]:
            metadata["jwks"]["keys"] = [key_from_jwk_dict(jwk).serialize(private=False) for jwk in metadata["jwks"]["keys"]]

        return metadata

    def is_revoked(self, issuer: Optional[str] = None, force_update: bool = False) -> bool:
        """
        Yield if the trust toward the issuer was revoked according to some trust model;
        This asusmed that  the isser exists, is valid, but is not trusted.

        :param issuer: The issuer
        :type issuer: str

        :returns: If the trust toward the issuer was revoked
        :rtype: bool
        """
        trust_source = self._get_trust_source(issuer, force_update)
        return trust_source.is_revoked()
    
    def revoke(self, issuer: Optional[str] = None) -> None:
        """
        Revoke the trust toward the issuer according to some trust model.

        :param issuer: The issuer
        :type issuer: str
        """
        trust_source = self._get_trust_source(issuer)
        trust_source.revoked = True
        self.db_engine.add_trust_source(trust_source.serialize())

    def get_policies(self, issuer: Optional[str] = None, force_update: bool = False) -> dict[str, any]:
        """
        Get the policies of a certain issuer according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The policies
        :rtype: dict[str, any]
        """
        trust_source = self._get_trust_source(issuer, force_update)

        if not trust_source.policies:
            raise Exception(
                f"no trust evaluator can provide policies for {issuer}: "
                f"searched among: {self.handlers_names}"
            )

        return trust_source.policies

    def get_jwt_header_trust_parameters(self, issuer: Optional[str] = None, force_update: bool = False) -> list[dict]:
        """
        Get the trust parameters of a certain issuer according to some trust model.

        :param issuer: The issuer
        :type issuer: str

        :returns: The trust parameters
        :rtype: list[dict]
        """
        trust_source = self._get_trust_source(issuer, force_update)

        headers_params = {}
        for handler in self.handlers:
            if getattr(handler, INCLUDE_JWT_HEADER_CONFIG_NAME, None):
                if header := handler.extract_jwt_header_trust_parameters(trust_source):
                    headers_params.update(header)
        return headers_params

    def build_metadata_endpoints(
        self, backend_name: str, entity_uri: str
    ) -> list[
        tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]
    ]:
        endpoints = []
        for handler in self.handlers:
            endpoints += handler.build_metadata_endpoints(backend_name, entity_uri)
        # Partially check for collissions in managed paths: this might happen if multiple configured
        # trust frameworks want to handle the same endpoints (check is not 100% exhaustive as paths are actually regexps)
        all_paths = [path for path, *_ in endpoints]
        if len(all_paths) > len(set(all_paths)):
            self._log_warning(
                "build_metadata_endpoints",
                f"found collision in metadata endpoint: {all_paths}",
            )
        return endpoints

    @staticmethod
    def from_config(
        config: dict, db_engine: DBEngine, default_client_id: str, mode: UpsertMode = "update_first"
    ) -> "CombinedTrustEvaluator":
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
                # every trust evaluation method might use their own client id
                # but a default one always therefore required
                if not handler_config["config"].get("client_id"):
                    handler_config["config"]["client_id"] = default_client_id

                trust_handler = dynamic_class_loader(
                    handler_config["module"],
                    handler_config["class"],
                    handler_config["config"],
                )
            except Exception as e:
                raise TrustConfigurationError(
                    f"invalid configuration for {handler_name}: {e}", e
                )

            if not isinstance(trust_handler, TrustHandlerInterface):
                raise TrustConfigurationError(
                    f"class {trust_handler.__class__} does not satisfy the interface TrustEvaluator"
                )

            handlers.append(trust_handler)
            logger.debug(
                f"TrustHandlers loaded: [{', '.join([str(i.__class__) for i in handlers])}]."
            )

        if not handlers:
            logger.warning("No configured trust model, using direct trust model")
            handlers.append(DirectTrustSdJwtVc())
            handlers.append(DirectTrustJar())

        return CombinedTrustEvaluator(handlers, db_engine, mode)
