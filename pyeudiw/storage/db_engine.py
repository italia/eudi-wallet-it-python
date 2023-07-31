import uuid
import importlib
from pyeudiw.storage.base_cache import BaseCache
from pyeudiw.storage.base_storage import BaseStorage

class DBEngine():
    def __init__(self, config: dict):
        self.cache = []
        self.storages = []
        
        for db_name, db_conf in config.items():
            storage_instance, cache_instance = self._handle_instance(db_conf)
            
            if storage_instance:
                self.storages.append(storage_instance)
                
            if cache_instance:
                self.cache.append(cache_instance)
    
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
        for storage in self.storages:
            storage.init_session(dpop_proof, attestation)
            
        return document_id

    def update_request_object(self, document_id: str, request_object: dict):
        for storage in self.storages:
            storage.update_request_object(document_id, request_object)

    def update_response_object(self, nonce: str, state: str, response_object: dict):
        for storage in self.storages:
            storage.update_response_object(nonce, state, response_object)