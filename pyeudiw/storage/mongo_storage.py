import pymongo
from datetime import datetime

from pymongo.results import UpdateResult

from pyeudiw.storage.base_storage import BaseStorage
from pyeudiw.storage.exceptions import ChainAlreadyExist, ChainNotExist


class MongoStorage(BaseStorage):
    def __init__(self, conf: dict, url: str, connection_params: dict = None) -> None:
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
            self.attestations = getattr(
                self.db, self.storage_conf["db_attestations_collection"]
            )

    def _retrieve_document_by_id(self, document_id: str) -> dict:
        self._connect()

        document = self.sessions.find_one({"document_id": document_id})

        if document is None:
            raise ValueError(f'Document with id {document_id} not found')

        return document

    def _retrieve_document_by_nonce_state(self, nonce: str, state: str | None) -> dict:
        self._connect()

        query = {"state": state, "nonce": nonce}

        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(
                f'Document with nonce {nonce} and state {state} not found')

        return document

    def _retrieve_document_by_state_and_session_id(self, state: str, session_id :str = ""):
        self._connect()

        query = {"state": state}
        if session_id:
            query["session_id"] = session_id
        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(
                f'Document with state {state} not found')

        return document

    def init_session(self, document_id: str, session_id: str, state: str) -> str:
        creation_date = datetime.timestamp(datetime.now())

        entity = {
            "document_id": document_id,
            "creation_date": creation_date,
            "state": state,
            "session_id": session_id,
            "finalized": False,
            "request_object": None,
            "response": None
        }

        self._connect()
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
                f"Cannot update document {document_id}')"
            )

        return update_result

    def update_request_object(self, document_id: str, request_object: dict):
        self._retrieve_document_by_id(document_id)
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
        self._retrieve_document_by_id(document_id)

        update_result: UpdateResult = self.collection.update_one(
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

    def update_response_object(self, nonce: str, state: str, response_object: dict):
        document = self._retrieve_document_by_nonce_state(nonce, state)
        document_id = document["_id"]
        documentStatus = self.sessions.update_one(
            {"_id": document_id},
            {"$set":
                {
                    "response_object": response_object
                },
             })

        return nonce, state, documentStatus

    def get_trust_attestation(self, entity_id: str):
        self._connect()
        return self.attestations.find_one({"entity_id": entity_id})

    def has_trust_attestation(self, entity_id: str):
        if self.get_trust_attestation({"entity_id": entity_id}):
            return True
        return False

    def add_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        if self.has_trust_attestation(entity_id):
            raise ChainAlreadyExist(
                f"Chain with entity id {entity_id} already exist")

        entity = {
            "entity_id": entity_id,
            "federation": {
                "chain": trust_chain,
                "exp": exp
            },
            "x509": {}
        }

        self.attestations.insert_one(entity)

        return entity_id

    def update_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        if not self.has_trust_attestation(entity_id):
            raise ChainNotExist(f"Chain with entity id {entity_id} not exist")

        documentStatus = self.attestations.update_one(
            {"entity_id": entity_id},
            {"$set":
                {
                    "federation": {
                        "chain": trust_chain,
                        "exp": exp
                    }
                }
             }
        )
        return documentStatus
