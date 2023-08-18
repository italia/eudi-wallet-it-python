import uuid
import logging
import importlib
from datetime import datetime
from typing import Callable, Union
from pyeudiw.storage.base_cache import BaseCache, RetrieveStatus
from pyeudiw.storage.base_storage import BaseStorage
from pyeudiw.storage.exceptions import StorageWriteError, EntryNotFound

logger = logging.getLogger(__name__)


class DBEngine():
    def __init__(self, config: dict):
        self.caches = []
        self.storages = []
        for db_name, db_conf in config.items():
            storage_instance, cache_instance = self._handle_instance(db_conf)

            if storage_instance:
                self.storages.append((db_name, storage_instance))

            if cache_instance:
                self.caches.append((db_name, cache_instance))

    def _handle_instance(self, instance: dict) -> dict[BaseStorage | None, BaseCache | None]:
        cache_conf = instance.get("cache", None)
        storage_conf = instance.get("storage", None)

        storage_instance = None
        if storage_conf:
            module = importlib.import_module(storage_conf["module"])
            instance_class = getattr(module, storage_conf["class"])
            storage_instance = instance_class(
                **storage_conf.get("init_params", {}))

        cache_instance = None
        if cache_conf:
            module = importlib.import_module(cache_conf["module"])
            instance_class = getattr(module, cache_conf["class"])
            cache_instance = instance_class(**cache_conf["init_params"])

        return storage_instance, cache_instance

    def init_session(self, session_id: str, state: str) -> str:
        document_id = str(uuid.uuid4())
        for db_name, storage in self.storages:
            try:
                storage.init_session(
                    document_id, session_id=session_id, state=state
                )
            except StorageWriteError as e:
                logger.critical(
                    f"Error while initializing session with document_id {document_id}. "
                    f"Cannot write document with id {document_id} on {db_name}: "
                    f"{e.__class__.__name__}: {e}"
                )
                raise e

        return document_id

    def write(self, method: str, *args, **kwargs):
        replica_count = 0
        _err_msg = f"Cannot apply write method '{method}' with {args} {kwargs}"
        for db_name, storage in self.storages:
            try:
                getattr(storage, method)(*args, **kwargs)
                replica_count += 1
            except Exception as e:
                logger.critical(
                    f"Error {_err_msg} on {db_name} {storage}: {str(e)}")

        if not replica_count:
            raise StorageWriteError(_err_msg)

        return replica_count

    def add_dpop_proof_and_attestation(self, document_id, dpop_proof: dict, attestation: dict):
        return self.write(
            "add_dpop_proof_and_attestation",
            document_id,
            dpop_proof=dpop_proof,
            attestation=attestation
        )

    def set_finalized(self, document_id: str):
        return self.write("set_finalized", document_id)

    def update_request_object(self, document_id: str, request_object: dict) -> int:
        return self.write("update_request_object", document_id, request_object)

    def update_response_object(self, nonce: str, state: str, response_object: dict) -> int:
        return self.write("update_response_object", nonce, state, response_object)

    def get(self, method: str, *args, **kwargs):
        for db_name, storage in self.storages:
            try:
                res = getattr(storage, method)(*args, **kwargs)
                if res:
                    return res

            except EntryNotFound as e:
                logger.critical(
                    f"Cannot find result by method {method} on {db_name} with {args} {kwargs}: {str(e)}"
                )

        raise EntryNotFound(f"Cannot find any result by method {method}")

    def get_trust_attestation(self, entity_id: str) -> Union[dict, None]:
        return self.get("get_trust_attestation", entity_id)

    def get_trust_anchor(self, entity_id: str) -> Union[dict, None]:
        return self.get("get_trust_anchor", entity_id)

    def has_trust_attestation(self, entity_id: str):
        return self.get_trust_attestation(entity_id)

    def has_trust_anchor(self, entity_id: str):
        return self.get_anchor(entity_id)

    def add_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        return self.write("add_trust_attestation", entity_id, trust_chain)

    def add_trust_anchor(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        return self.write("add_trust_anchor", entity_id, trust_chain, exp)

    def update_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        return self.write("update_trust_attestation", entity_id, trust_chain, exp)

    def update_trust_anchor(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        return self.write("update_trust_anchor", entity_id, trust_chain, exp)

    def _cache_try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> tuple[dict, RetrieveStatus, int]:
        for i, cache in enumerate(self.caches):
            try:
                cache_object, status = cache.try_retrieve(
                    object_name, on_not_found)
                return cache_object, status, i
            except Exception:
                logger.critical(
                    "Cannot retrieve or write cache object with identifier {object_name} on database {db_name}")
        raise ConnectionRefusedError(
            "Cannot write cache object on any instance")

    def try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> dict:
        # if no cache instance exist return the object
        if len(self.caches):
            return on_not_found()

        # if almost one cache instance exist try to retrieve
        cache_object, status, idx = self._cache_try_retrieve(
            object_name, on_not_found)

        # if the status is retrieved return the object
        if status == RetrieveStatus.RETRIEVED:
            return cache_object

        # else try replicate the data on all the other istances
        replica_instances = self.caches[:idx] + self.caches[idx + 1:]

        for cache_name, cache in replica_instances:
            try:
                cache.set(cache_object)
            except Exception:
                logger.critical(
                    "Cannot replicate cache object with identifier {object_name} on cache {cache_name}")

        return cache_object

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        for cache_name, cache in self.caches:
            cache_object = None
            try:
                cache_object = cache.overwrite(object_name, value_gen_fn)
            except Exception:
                logger.critical(
                    "Cannot overwrite cache object with identifier {object_name} on cache {cache_name}"
                )
            return cache_object

    def exists_by_state_and_session_id(self, state: str, session_id: str = "") -> bool:
        for db_name, storage in self.storages:
            found = storage.exists_by_state_and_session_id(
                state=state, session_id=session_id)
            if found:
                return True
        return False

    def get_by_state(self, state: str):
        return self.get_by_state_and_session_id(state=state)

    def get_by_nonce_state(self, state: str, nonce: str):
        return self.get('get_by_nonce_state', state=state, nonce=nonce)

    def get_by_state_and_session_id(self, state: str, session_id: str = ""):
        return self.get("get_by_state_and_session_id", state, session_id)

    def get_by_session_id(self, session_id: str):
        return self.get("get_by_session_id", session_id)
