import pymongo
import datetime as dt
from datetime import datetime

from pymongo.results import UpdateResult

from pyeudiw.storage.base_storage import (
    BaseStorage,
    TrustType,
    trust_type_map,
    trust_attestation_field_map,
    trust_anchor_field_map
)
from pyeudiw.storage.exceptions import (
    ChainAlreadyExist,
    ChainNotExist,
    StorageEntryUpdateFailed
)
from typing import Union


class MongoStorage(BaseStorage):
    def __init__(self, conf: dict, url: str, connection_params: dict = {}) -> None:
        super().__init__()
        self.storage_conf = conf
        self.url = url
        self.connection_params = connection_params

        self.client = None
        self.db = None

        self.set_session_retention_ttl(conf.get("data_ttl", None))

    @property
    def is_connected(self) -> bool:
        if not self.client:
            return False
        try:
            self.client.server_info()
        except pymongo.errors.InvalidOperation:
            return False

        return True

    def _connect(self):
        if not self.is_connected:
            self.client = pymongo.MongoClient(
                self.url, **self.connection_params
            )
            self.db = getattr(self.client, self.storage_conf["db_name"])
            self.sessions = getattr(
                self.db, self.storage_conf["db_sessions_collection"]
            )
            self.trust_attestations = getattr(
                self.db, self.storage_conf["db_trust_attestations_collection"]
            )
            self.trust_anchors = getattr(
                self.db, self.storage_conf["db_trust_anchors_collection"]
            )
            self.trust_sources = getattr(
                self.db, self.storage_conf["db_trust_sources_collection"]
            )

    def close(self):
        self._connect()
        self.client.close()

    def get_by_id(self, document_id: str) -> dict:
        self._connect()
        document = self.sessions.find_one({"document_id": document_id})

        if document is None:
            raise ValueError(f'Document with id {document_id} not found')

        return document

    def get_by_nonce_state(self, nonce: str, state: str | None) -> dict:
        self._connect()
        query = {"state": state, "nonce": nonce}
        if not state:
            query.pop('state')

        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(
                f'Document with nonce {nonce} and state {state} not found')

        return document

    def get_by_session_id(self, session_id: str) -> Union[dict, None]:
        self._connect()
        query = {"session_id": session_id}
        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(
                f'Document with session id {session_id} not found.'
            )

        return document

    def get_by_state_and_session_id(self, state: str, session_id: str = "") -> Union[dict, None]:
        self._connect()
        query = {"state": state}
        if session_id:
            query["session_id"] = session_id
        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(
                f'Document with state {state} not found.'
            )

        return document

    def init_session(self, document_id: str, session_id: str, state: str) -> str:
        entity = {
            "document_id": document_id,
            "creation_date": dt.datetime.now(tz=dt.timezone.utc),
            "state": state,
            "session_id": session_id,
            "finalized": False,
            "internal_response": None,
        }

        try:
            self._connect()
        except Exception as e:
            raise e

        self.sessions.insert_one(entity)

        return document_id

    def set_session_retention_ttl(self, ttl: int) -> None:
        self._connect()

        if not ttl:
            if self.sessions.index_information().get("creation_date_1"):
                self.sessions.drop_index("creation_date_1")
        else:
            self.sessions.create_index(
                [("creation_date", pymongo.ASCENDING)], expireAfterSeconds=ttl)

    def has_session_retention_ttl(self) -> bool:
        self._connect()
        return self.sessions.index_information().get("creation_date_1") is not None

    def add_dpop_proof_and_attestation(self, document_id: str, dpop_proof: dict, attestation: dict) -> UpdateResult:
        self._connect()
        update_result: UpdateResult = self.sessions.update_one(
            {"document_id": document_id},
            {
                "$set": {
                    "dpop_proof": dpop_proof,
                    "attestation": attestation,
                }
            })
        if update_result.matched_count != 1 or update_result.modified_count != 1:
            raise ValueError(
                f"Cannot update document {document_id}'."
            )

        return update_result

    def update_request_object(self, document_id: str, request_object: dict) -> UpdateResult:
        self.get_by_id(document_id)
        documentStatus = self.sessions.update_one(
            {"document_id": document_id},
            {
                "$set": {
                    "request_object": request_object,
                    "nonce": request_object["nonce"],
                    "state": request_object["state"],
                }
            }
        )
        if documentStatus.matched_count != 1 or documentStatus.modified_count != 1:
            raise ValueError(
                f"Cannot update document {document_id}')"
            )
        return documentStatus

    def set_finalized(self, document_id: str):
        self.get_by_id(document_id)

        update_result: UpdateResult = self.sessions.update_one(
            {"document_id": document_id},
            {
                "$set": {
                    "finalized": True
                },
            }
        )
        if update_result.matched_count != 1:  # or update_result.modified_count != 1:
            raise ValueError(
                f"Cannot update document {document_id}'"
            )
        return update_result

    def update_response_object(self, nonce: str, state: str, internal_response: dict) -> UpdateResult:
        document = self.get_by_nonce_state(nonce, state)
        document_id = document["_id"]
        document_status = self.sessions.update_one(
            {"_id": document_id},
            {"$set":
                {
                    "internal_response": internal_response
                },
             })

        return document_status

    def _get_db_entity(self, collection: str, entity_id: str) -> dict | None:
        self._connect()
        db_collection = getattr(self, collection)
        return db_collection.find_one({"entity_id": entity_id})
    
    def get_trust_source(self, entity_id: str) -> dict | None:
        return self._get_db_entity(
            self.storage_conf["db_trust_sources_collection"], entity_id
        )

    def get_trust_attestation(self, entity_id: str) -> dict | None:
        return self._get_db_entity(
            self.storage_conf["db_trust_attestations_collection"], 
            entity_id
        )

    def get_trust_anchor(self, entity_id: str) -> dict | None:
        return self._get_db_entity(
            self.storage_conf["db_trust_anchors_collection"], 
            entity_id
        )

    def _has_db_entity(self, collection: str, entity_id: str) -> bool:
        return self._get_db_entity(collection, entity_id) is not None

    def has_trust_attestation(self, entity_id: str) -> bool:
        return self._has_db_entity(
            self.storage_conf["db_trust_attestations_collection"], 
            entity_id
        )

    def has_trust_anchor(self, entity_id: str) -> bool:
        return self._has_db_entity(
            self.storage_conf["db_trust_anchors_collection"], 
            entity_id
        )
    
    def has_trust_source(self, entity_id: str) -> bool:
        return self._has_db_entity(
            self.storage_conf["db_trust_sources_collection"], 
            entity_id
        )

    def _add_entry(
        self,
        collection: str,
        entity_id: str,
        attestation: Union[str, dict],
        exp: datetime
    ) -> str:

        meth_suffix = collection[:-1]
        if getattr(self, f"has_{meth_suffix}")(entity_id):
            # TODO: bug detected. Commentato l'update e lasciato il raise dell'eccezione
            # l'attestation passata come parametro non è quello che si aspetta il metodo di update
            # bensì è l'intero oggetto trust_attestation

            # # update it
            # getattr(self, f"update_{meth_suffix}")(entity_id, attestation, exp)
            # return entity_id
            raise ChainAlreadyExist(f"Chain with entity id {entity_id} already exists")

        db_collection = getattr(self, collection)
        db_collection.insert_one(attestation)
        return entity_id

    def _update_attestation_metadata(self, entity: dict, attestation: list[str], exp: datetime, trust_type: TrustType, jwks: list[dict]):
        trust_name = trust_type_map[trust_type]
        trust_field = trust_attestation_field_map.get(trust_type, None)

        trust_entity = entity.get(trust_name, {})

        if trust_field and attestation:
            trust_entity[trust_field] = attestation
        if exp:
            trust_entity["exp"] = exp
        if jwks:
            trust_entity["jwks"] = jwks

        entity[trust_name] = trust_entity

        return entity

    def _update_anchor_metadata(self, entity: dict, attestation: list[str], exp: datetime, trust_type: TrustType):
        trust_name = trust_type_map[trust_type]
        trust_field = trust_anchor_field_map.get(trust_type, None)

        trust_entity = entity.get(trust_name, {})

        if trust_field and attestation:
            trust_entity[trust_field] = attestation
        trust_entity["exp"] = exp

        entity[trust_name] = trust_entity

        return entity

    def add_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime, trust_type: TrustType, jwks: list[dict]) -> str:
        entity = {
            "entity_id": entity_id,
            "federation": {},
            "x509": {},
            "direct_trust_sd_jwt_vc": {},
            "metadata": {}
        }

        updated_entity = self._update_attestation_metadata(
            entity, attestation, exp, trust_type, jwks)

        return self._add_entry(
            self.storage_conf["db_trust_attestations_collection"], entity_id, updated_entity, exp
        )
    
    def add_trust_source(self, entity_id: str, trust_source: dict) -> str:
        return self._add_entry(
            "trust_sources", entity_id, trust_source, trust_source.get("exp")
        )

    def add_trust_attestation_metadata(self, entity_id: str, metadata_type: str, metadata: dict):
        entity = self._get_db_entity(self.storage_conf["db_trust_attestations_collection"], entity_id)

        if entity is None:
            raise ValueError(
                f'Document with entity_id {entity_id} not found.'
            )

        entity["metadata"][metadata_type] = metadata

        return self._update_trust_attestation(self.storage_conf["db_trust_attestations_collection"], entity_id, entity)

    def add_trust_anchor(self, entity_id: str, entity_configuration: str, exp: datetime, trust_type: TrustType):
        if self.has_trust_anchor(entity_id):
            return self.update_trust_anchor(entity_id, entity_configuration, exp, trust_type)
        else:
            entity = {
                "entity_id": entity_id,
                "federation": {},
                "x509": {}
            }

            updated_entity = self._update_anchor_metadata(
                entity, entity_configuration, exp, trust_type)
            return self._add_entry(self.storage_conf["db_trust_anchors_collection"], entity_id, updated_entity, exp)

    def _update_trust_attestation(self, collection: str, entity_id: str, entity: dict) -> str:
        if not self._has_db_entity(collection, entity_id):
            raise ChainNotExist(f"Chain with entity id {entity_id} not exist")

        documentStatus = self.trust_attestations.update_one(
            {"entity_id": entity_id},
            {"$set": entity}
        )
        return documentStatus

    def update_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime, trust_type: TrustType, jwks: list[dict]) -> str:
        old_entity = self._get_db_entity(
            self.storage_conf["db_trust_attestations_collection"], entity_id) or {}
        upd_entity = self._update_attestation_metadata(
            old_entity, attestation, exp, trust_type, jwks)

        return self._update_trust_attestation(self.storage_conf["db_trust_attestations_collection"], entity_id, upd_entity)

    def update_trust_anchor(self, entity_id: str, entity_configuration: str, exp: datetime, trust_type: TrustType) -> str:
        old_entity = self._get_db_entity(
            self.storage_conf["db_trust_attestations_collection"], entity_id) or {}
        upd_entity = self._update_anchor_metadata(
            old_entity, entity_configuration, exp, trust_type)

        if not self.has_trust_anchor(entity_id):
            raise ChainNotExist(f"Chain with entity id {entity_id} not exist")

        documentStatus = self.trust_anchors.update_one(
            {"entity_id": entity_id},
            {"$set": upd_entity}
        )
        if not documentStatus.matched_count:
            raise StorageEntryUpdateFailed(
                "Trust Anchor matched count is ZERO"
            )

        return documentStatus
