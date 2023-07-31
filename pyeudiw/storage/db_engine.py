import uuid
import logging
import importlib
from pyeudiw.storage.base_cache import BaseCache
from pyeudiw.storage.base_storage import BaseStorage

logger = logging.getLogger("openid4vp_backend")

class DBEngine():
    def __init__(self, config: dict):
        self.cache = []
        self.storages = []
        
        for db_name, db_conf in config.items():
            storage_instance, cache_instance = self._handle_instance(db_conf)
            
            if storage_instance:
                self.storages.append((db_name, storage_instance))
                
            if cache_instance:
                self.cache.append((db_name, cache_instance))
    
    def _handle_instance(instance: dict) -> dict[BaseStorage | None, BaseCache | None]:
        cache_conf = instance.get("cache", None)
        storage_conf = instance.get("storage", None)
        
        storage_instance = None    
        if storage_conf:
            module = importlib.import_module(storage_conf["module"])
            instance_class = getattr(module, storage_conf["class"])
            
            storage_instance = instance_class(storage_conf["config"])
            
        cache_instance = None
        if cache_conf:
            module = importlib.import_module(cache_conf["module"])
            instance_class = getattr(module, cache_conf["class"])
            
            cache_instance = instance_class(cache_conf["config"])
            
        return storage_instance, cache_instance
    
    def init_session(self, dpop_proof: dict, attestation: dict):
        document_id = str(uuid.uuid4())
        for db_name, storage in self.storages:
            try:
                storage.init_session(dpop_proof, attestation)
            except Exception as e:
                logger.critical("Cannot write document with id {document_id} on {db_name}")
            
        return document_id

    def update_request_object(self, document_id: str, nonce: str, state: str, request_object: dict):
        for db_name, storage in self.storages:
            try:
                storage.update_request_object(document_id, nonce, state, request_object)
            except Exception as e:
                logger.critical("Cannot update document with id {document_id} on {db_name}")

    def update_response_object(self, nonce: str, state: str, response_object: dict):
        for db_name, storage in self.storages:
            try:
                storage.update_response_object(nonce, state, response_object)
            except Exception as e:
                logger.critical("Cannot update document with nonce {nonce} and state {state} on {db_name}")