import pymongo
from datetime import datetime

from pymongo.results import UpdateResult

from pyeudiw.storage.base_storage import BaseStorage
from pyeudiw.storage.exceptions import (
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

    def _connect(self):
        if not self.client or not self.client.server_info():
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

    def get_by_session_id(self, session_id: str):
        self._connect()

        query = {"session_id": session_id}
        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(
                f'Document with session id {session_id} not found.'
            )

        return document

    def get_by_state_and_session_id(self, state: str, session_id: str = ""):
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
            "creation_date": datetime.now().isoformat(),
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

    def add_dpop_proof_and_attestation(self, document_id: str, dpop_proof: dict, attestation: dict):
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

    def update_request_object(self, document_id: str, request_object: dict):
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
        if update_result.matched_count != 1 or update_result.modified_count != 1:
            raise ValueError(
                f"Cannot update document {document_id}')"
            )
        return update_result

    def update_response_object(self, nonce: str, state: str, internal_response: dict):
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

    def _get_trust_attestation(self, collection: str, entity_id: str) -> dict:
        self._connect()
        db_collection = getattr(self, collection)
        return db_collection.find_one({"entity_id": entity_id})

    def get_trust_attestation(self, entity_id: str):
        return self._get_trust_attestation("trust_attestations", entity_id)

    def get_trust_anchor(self, entity_id: str):
        return self._get_trust_attestation("trust_anchors", entity_id)

    def _has_trust_attestation(self, collection: str, entity_id: str):
        return self._get_trust_attestation(collection, entity_id)

    def has_trust_attestation(self, entity_id: str):
        return self._has_trust_attestation("trust_attestations", entity_id)

    def has_trust_anchor(self, entity_id: str):
        return self._has_trust_attestation("trust_anchors", entity_id)

    def _add_entry(
        self,
        collection: str,
        entity_id: str,
        attestation: Union[str, dict],
        exp: datetime
    ) -> str:

        meth_suffix = collection[:-1]
        if getattr(self, f"has_{meth_suffix}")(entity_id):
            # update it
            getattr(self, f"update_{meth_suffix}")(entity_id, attestation, exp)
            return entity_id
            # raise ChainAlreadyExist(
            # f"Chain with entity id {entity_id} already exist"
            # )

        db_collection = getattr(self, collection)
        db_collection.insert_one(attestation)
        return entity_id

    def add_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime):
        entity = {
            "entity_id": entity_id,
            "federation": {
                "chain": attestation,
                "exp": exp
            },
            "x509": {}
        }

        self._add_entry(
            "trust_attestations", entity_id, entity, exp
        )

    def add_trust_anchor(self, entity_id: str, entity_configuration: Union[dict, str], exp: datetime):
        entry = {
            "entity_id": entity_id,
            "federation": {
                "entity_configuration": entity_configuration,
                "exp": exp
            },
            "x509": {}  # TODO x509
        }
        if self.has_trust_anchor(entity_id):
            self.update_trust_anchor(entity_id, entity_configuration, exp)
        else:
            self._add_entry("trust_anchors", entity_id, entry, exp)

    def _update_trust_attestation(self, collection: str, entity_id: str, entity: dict, exp: datetime) -> str:
        if not self._has_trust_attestation(collection, entity_id):
            raise ChainNotExist(f"Chain with entity id {entity_id} not exist")

        documentStatus = self.trust_attestations.update_one(
            {"entity_id": entity_id},
            {"$set": entity}
        )
        return documentStatus

    def update_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        entity = {
            "federation": {
                "chain": trust_chain,
                "exp": exp
            }
        }

        return self._update_trust_attestation("trust_attestations", entity_id, entity, exp)

    def update_trust_anchor(self, entity_id: str, entity_configuration: dict, exp: datetime) -> str:
        entity = {
            "federation": {
                "entity_configuration": entity_configuration,
                "exp": exp
            }
        }

        if not self.has_trust_anchor(entity_id):
            raise ChainNotExist(f"Chain with entity id {entity_id} not exist")

        documentStatus = self.trust_anchors.update_one(
            {"entity_id": entity_id},
            {"$set": entity}
        )
        if not documentStatus.matched_count:
            raise StorageEntryUpdateFailed(
                "Trust Anchor matched count is ZERO"
            )

        return documentStatus
