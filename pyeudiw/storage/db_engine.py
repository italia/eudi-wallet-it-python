import uuid
import logging
import importlib
from datetime import datetime
from typing import Callable, Union
from pyeudiw.storage.base_cache import BaseCache, RetrieveStatus
from pyeudiw.storage.base_storage import BaseStorage
from pyeudiw.storage.exceptions import ReplicaError

logger = logging.getLogger("openid4vp.storage.db")


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

            storage_instance = instance_class(**storage_conf["init_params"])

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
                    document_id, session_id=session_id, state=state)
            except Exception as e:
                logger.critical(
                    f"Error while initializing session with document_id {document_id}. "
                    f"Cannot write document with id {document_id} on {db_name}: "
                    f"{e.__class__.__name__}: {e}")

        return document_id

    def add_dpop_proof_and_attestation(self, document_id, dpop_proof: dict, attestation: dict):
        replica_count = 0
        for db_name, storage in self.storages:
            try:
                storage.add_dpop_proof_and_attestation(
                    document_id, dpop_proof=dpop_proof, attestation=attestation)
                replica_count += 1
            except Exception as e:
                logger.critical(f"Error {str(e)}")
                logger.critical(
                    f"Cannot update document with id {document_id} on {db_name}")

        if replica_count == 0:
            raise ReplicaError(
                f"Cannot update document {document_id} on any instance")

        return replica_count

    def set_finalized(self, document_id: str):
        replica_count = 0
        for db_name, storage in self.storages:
            try:
                storage.set_finalized(document_id)
                replica_count += 1
            except Exception as e:
                logger.critical(f"Error {str(e)}")
                logger.critical(
                    f"Cannot update document with id {document_id} on {db_name}")

        if replica_count == 0:
            raise Exception(
                f"Cannot update document {document_id} on any instance")

        return replica_count

    def update_request_object(self, document_id: str, request_object: dict) -> int:
        replica_count = 0
        for db_name, storage in self.storages:
            try:
                storage.update_request_object(
                    document_id, request_object)
                replica_count += 1
            except Exception as e:
                logger.critical(f"Error {str(e)}")
                logger.critical(
                    f"Cannot update document with id {document_id} on {db_name}")

        if replica_count == 0:
            raise Exception(
                f"Cannot update document {document_id} on any instance")

        return replica_count

    def update_response_object(self, nonce: str, state: str, response_object: dict) -> int:
        replica_count = 0
        for db_name, storage in self.storages:
            try:
                storage.update_response_object(nonce, state, response_object)
                replica_count += 1
            except Exception as e:
                logger.critical(f"Error {str(e)}")
                logger.critical(
                    f"Cannot update document with nonce {nonce} and state {state} on {db_name}")

        if replica_count == 0:
            raise ReplicaError(
                f"Cannot update document with state {state} and nonce {nonce} on any instance")

        return replica_count

    def get_trust_attestation(self, entity_id: str) -> Union[dict, None]:
        for db_name, storage in self.storages:
            try:
                chain = storage.get_trust_attestation(entity_id)

                if chain:
                    return chain

            except Exception as e:
                logger.critical(f"Error {str(e)}")
                logger.critical(
                    f"Cannot find chain {entity_id} on {db_name}")

        raise Exception(f"Cannot find chain {entity_id} on any instance")

    def has_trust_attestation(self, entity_id: str):
        if self.get_trust_attestation(entity_id) is not None:
            return True
        return False

    def add_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        replica_count = 0
        for db_name, storage in self.storages:
            try:
                storage.add_trust_attestation(entity_id, trust_chain, exp)
                replica_count += 1
            except Exception:
                logger.critical(
                    "Cannot add chain with entity_id {entity_id} on database {db_name}")

        if replica_count == 0:
            raise ReplicaError(
                f"Cannot add chain {entity_id} on any instance")

    def update_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        replica_count = 0
        for db_name, storage in self.storages:
            try:
                storage.update_trust_attestation(entity_id, trust_chain, exp)
                replica_count += 1
            except Exception:
                logger.critical(
                    "Cannot add chain with entity_id {entity_id} on database {db_name}")

        if replica_count == 0:
            raise ReplicaError(
                f"Cannot update chain {entity_id} on any instance")

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
        istances_len = len(self.caches)

        # if no cache instance exist return the object
        if istances_len == 0:
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
                    "Cannot overwrite cache object with identifier {object_name} on cache {cache_name}")

            return cache_object

    def exists_by_state_and_session_id(self, state: str, session_id :str = "") -> bool:
        for db_name, storage in self.storages:
            found = storage.exists_by_state_and_session_id(
                state=state, session_id=session_id)
            if found:
                return True
        return False

    def get_by_state(self, state: str):
        return self.get_by_state_and_session_id(state=state)

    def get_by_state_and_session_id(self, state: str, session_id :str = ""):
        for db_name, storage in self.storages:
            try:
                document = storage._retrieve_document_by_state_and_session_id(
                    state, session_id)
                return document
            except ValueError:
                logger.debug(
                    f"Document object with state {state} and session_id {session_id} not found in db {db_name}")
        
        _msg = f"Document object with state {state} and session_id {session_id} not found"
        logger.error(_msg)
        raise ValueError(_msg)
