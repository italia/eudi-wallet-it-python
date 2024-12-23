import uuid
from datetime import datetime
from typing import Callable, Union, Tuple
from pyeudiw.storage.base_cache import BaseCache, RetrieveStatus
from pyeudiw.storage.base_storage import BaseStorage, TrustType
from pyeudiw.storage.exceptions import (
    ChainNotExist,
    StorageWriteError,
    EntryNotFound
)
from pyeudiw.tools.base_logger import BaseLogger

from .base_db import BaseDB

from pyeudiw.tools.utils import dynamic_class_loader


class DBEngine(BaseStorage, BaseCache, BaseLogger):
    """
    DB Engine class.
    """

    def __init__(self, config: dict):
        """
        Create a DB Engine instance.

        :param config: the configuration of all the DBs.
        :type config: dict
        """
        self.caches: list[Tuple[str, BaseCache]] = []
        self.storages: list[Tuple[str, BaseStorage]] = []

        for db_name, db_conf in config.items():
            storage_instance, cache_instance = self._handle_instance(db_conf)

            if storage_instance:
                self.storages.append((db_name, storage_instance))

            if cache_instance:
                self.caches.append((db_name, cache_instance))

    def init_session(self, session_id: str, state: str) -> str:
        document_id = str(uuid.uuid4())
        for db_name, storage in self.storages:
            try:
                storage.init_session(
                    document_id, session_id=session_id, state=state
                )
            except StorageWriteError as e:
                self._log_critical(
                    e.__class__.__name__,
                    (
                        f"Error while initializing session with document_id {document_id}. "
                        f"Cannot write document with id {document_id} on {db_name}: {e}"
                    )
                )
                raise e

        return document_id

    def close(self):
        self._close_list(self.storages)
        self._close_list(self.caches)

    def write(self, method: str, *args, **kwargs):
        """
        Perform a write operation on the storages.

        :param method: the method to call.
        :type method: str
        :param args: the arguments to pass to the method.
        :type args: Any
        :param kwargs: the keyword arguments to pass to the method.
        :type kwargs: Any

        :raises StorageWriteError: if the write operation fails on all the storages.

        :returns: the number of replicas where the write operation is successful.
        :rtype: int
        """

        replica_count = 0
        _err_msg = f"Cannot apply write method '{method}' with {args} {kwargs}"
        for db_name, storage in self.storages:
            try:
                getattr(storage, method)(*args, **kwargs)
                replica_count += 1
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Error {_err_msg} on {db_name}: {e}"
                )

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

    def get(self, method: str, *args, **kwargs) -> Union[dict, None]:
        """
        Perform a get operation on the storages.

        :param method: the method to call.
        :type method: str
        :param args: the arguments to pass to the method.
        :type args: Any
        :param kwargs: the keyword arguments to pass to the method.
        :type kwargs: Any

        :raises EntryNotFound: if the entry is not found on any storage.

        :returns: the result of the first elment found on DBs.
        :rtype: Union[dict, None]
        """

        for db_name, storage in self.storages:
            try:
                res = getattr(storage, method)(*args, **kwargs)
                if res:
                    return res

            except EntryNotFound as e:
                self._log_debug(
                    e.__class__.__name__,
                    f"Cannot find result by method {method} on {db_name} with {args} {kwargs}: {str(e)}"
                )

        raise EntryNotFound(f"Cannot find any result by method {method}")

    def get_trust_attestation(self, entity_id: str) -> Union[dict, None]:
        return self.get("get_trust_attestation", entity_id)

    def get_trust_anchor(self, entity_id: str) -> Union[dict, None]:
        return self.get("get_trust_anchor", entity_id)

    def has_trust_attestation(self, entity_id: str) -> bool:
        return self.get_trust_attestation(entity_id) is not None

    def has_trust_anchor(self, entity_id: str) -> bool:
        return self.get_trust_anchor(entity_id) is not None
    
    def has_trust_source(self, entity_id: str) -> bool:
        return self.get_trust_source(entity_id) is not None

    def add_trust_attestation(self, entity_id: str, attestation: list[str] = [], exp: datetime = None, trust_type: TrustType = TrustType.FEDERATION, jwks: list[dict] = []) -> str:
        return self.write("add_trust_attestation", entity_id, attestation, exp, trust_type, jwks)

    def add_trust_attestation_metadata(self, entity_id: str, metadat_type: str, metadata: dict) -> str:
        return self.write("add_trust_attestation_metadata", entity_id, metadat_type, metadata)
    
    def add_trust_source(self, trust_source: dict) -> str:
        return self.write("add_trust_source", trust_source)    

    def get_trust_source(self, entity_id: str) -> dict:
        return self.get("get_trust_source", entity_id)

    def add_trust_anchor(self, entity_id: str, entity_configuration: str, exp: datetime, trust_type: TrustType = TrustType.FEDERATION) -> str:
        return self.write("add_trust_anchor", entity_id, entity_configuration, exp, trust_type)

    def update_trust_attestation(self, entity_id: str, attestation: list[str] = [], exp: datetime = None, trust_type: TrustType = TrustType.FEDERATION, jwks: list[dict] = []) -> str:
        return self.write("update_trust_attestation", entity_id, attestation, exp, trust_type, jwks)

    def add_or_update_trust_attestation(self, entity_id: str, attestation: list[str] = [], exp: datetime = None, trust_type: TrustType = TrustType.FEDERATION, jwks: list[dict] = []) -> str:
        try:
            self.get_trust_attestation(entity_id)
            return self.write("update_trust_attestation", entity_id, attestation, exp, trust_type, jwks)
        except (EntryNotFound, ChainNotExist):
            return self.write("add_trust_attestation", entity_id, attestation, exp, trust_type, jwks)

    def update_trust_anchor(self, entity_id: str, entity_configuration: dict, exp: datetime, trust_type: TrustType = TrustType.FEDERATION) -> str:
        return self.write("update_trust_anchor", entity_id, entity_configuration, exp, trust_type)

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
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Cannot replicate cache object with identifier {object_name} on cache {cache_name}"
                )

        return cache_object

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        for cache_name, cache in self.caches:
            cache_object = None
            try:
                cache_object = cache.overwrite(object_name, value_gen_fn)
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Cannot overwrite cache object with identifier {object_name} on cache {cache_name}"
                )
            return cache_object

    def exists_by_state_and_session_id(self, state: str, session_id: str = "") -> bool:
        for db_name, storage in self.storages:
            found = storage.exists_by_state_and_session_id(
                state=state, session_id=session_id)
            if found:
                return True
        return False

    def get_by_state(self, state: str) -> Union[dict, None]:
        return self.get_by_state_and_session_id(state=state)

    def get_by_nonce_state(self, state: str, nonce: str) -> Union[dict, None]:
        return self.get('get_by_nonce_state', state=state, nonce=nonce)

    def get_by_state_and_session_id(self, state: str, session_id: str = "") -> Union[dict, None]:
        return self.get("get_by_state_and_session_id", state, session_id)

    def get_by_session_id(self, session_id: str) -> Union[dict, None]:
        return self.get("get_by_session_id", session_id)

    @property
    def is_connected(self):
        _connected = False
        _cons = {}
        for db_name, storage in self.storages:
            try:
                _connected = storage.is_connected
                _cons[db_name] = _connected
            except Exception as e:
                self._log_debug(
                    e.__class__.__name__,
                    f"Error while checking db engine connection on {db_name}: {e} "
                )

        if True in _cons.values() and not all(_cons.values()):
            self._log_warning(
                "DB Engine",
                f"Not all the storage are found available, storages misalignment: "
                f"{_cons}"
            )

        return _connected

    def _cache_try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> tuple[dict, RetrieveStatus, int]:
        """
        Try to retrieve an object from the cache. If the object is not found, call the on_not_found function.

        :param object_name: the name of the object to retrieve.
        :type object_name: str
        :param on_not_found: the function to call if the object is not found.
        :type on_not_found: Callable[[], str]

        :raises ConnectionRefusedError: if the object cannot be retrieved on any instance.

        :returns: a tuple with the retrieved object, a status and the index of the cache instance.
        :rtype: tuple[dict, RetrieveStatus, int]
        """

        for i, (cache_name, cache_istance) in enumerate(self.caches):
            try:
                cache_object, status = cache_istance.try_retrieve(
                    object_name, on_not_found)
                return cache_object, status, i
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Cannot retrieve cache object with identifier {object_name} on cache database {cache_name}"
                )
        raise ConnectionRefusedError(
            "Cannot write cache object on any instance"
        )

    def _close_list(self, db_list: list[Tuple[str, BaseDB]]) -> None:
        """
        Close a list of db.

        :param db_list: the list of db to close.
        :type db_list: list[Tuple[str,BaseDB]]

        :raises Exception: if an error occurs while closing a db.
        """

        for db_name, db in db_list:
            try:
                db.close()
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Error while closing db engine {db_name}: {e}"
                )
                raise e

    def _handle_instance(self, instance: dict) -> tuple[BaseStorage | None, BaseCache | None]:
        """
        Handle the initialization of a storage/cache instance.

        :param instance: the instance configuration.
        :type instance: dict

        :returns: a tuple with the storage and cache instance.
        :rtype: tuple[BaseStorage | None, BaseCache | None]
        """
        cache_conf = instance.get("cache", None)
        storage_conf = instance.get("storage", None)

        storage_instance = None
        if storage_conf:
            storage_instance = dynamic_class_loader(
                storage_conf["module"],
                storage_conf["class"],
                storage_conf.get("init_params", {})
            )

        cache_instance = None
        if cache_conf:
            cache_instance = dynamic_class_loader(
                cache_conf["module"],
                cache_conf["class"],
                cache_conf.get("init_params", {})
            )

        return storage_instance, cache_instance
