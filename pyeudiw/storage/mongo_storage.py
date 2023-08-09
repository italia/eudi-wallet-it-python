import pymongo
from datetime import datetime
from pyeudiw.storage.base_storage import BaseStorage
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header
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
                self.url, **self.connection_params)
            self.db = getattr(self.client, self.storage_conf["db_name"])
            self.sessions = getattr(
                self.db, self.storage_conf["db_sessions_collection"])
            self.chains = getattr(
                self.db, self.storage_conf["db_chains_collection"])

    def _retrieve_document_by_id(self, document_id: str) -> dict:
        self._connect()

        document = self.sessions.find_one({"document_id": document_id})

        if document is None:
            raise ValueError(f'Document with id {document_id} not found')

        return document

    def _retrieve_document_by_nonce_state(self, nonce: str | None, state: str) -> dict:
        self._connect()

        query = {"state": state, "nonce": nonce}

        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(
                f'Document with nonce {nonce} and state {state} not found')

        return document

    def init_session(self, document_id: str, dpop_proof: dict, attestation: dict) -> str:
        creation_date = datetime.timestamp(datetime.now())

        entity = {
            "document_id": document_id,
            "creation_date": creation_date,
            "dpop_proof": dpop_proof,
            "attestation": attestation,
            "request_object": None,
            "response": None
        }

        self._connect()
        self.sessions.insert_one(entity)

        return document_id

    def update_request_object(self, document_id: str, nonce: str, state: str, request_object: dict) -> tuple[str, str, dict]:
        self._retrieve_document_by_id(document_id)

        documentStatus = self.sessions.update_one(
            {"document_id": document_id},
            {
                "$set": {
                    "nonce": nonce,
                    "state": state,
                    "request_object": request_object
                }
            }
        )
        return nonce, state, documentStatus

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
    
    def find_chain(self, entity_id: str):
        self._connect()
        return self.chains.find_one({"entity_id": entity_id})

    def has_chain(self, entity_id: str):
        if self.find_chain({"entity_id": entity_id}):
            return True
        return False

    def add_chain(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        if self.has_chain(entity_id):
            raise ChainAlreadyExist(f"Chain with entity id {entity_id} already exist")
        
        entity = {
            "entity_id": entity_id,
            "federation": {
                "chain": trust_chain,
                "exp": exp
            },
            "x509": {}
        }
        
        self.chains.insert_one(entity)
        
        return entity_id
    
    def update_chain(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        if not self.has_chain(entity_id):
            raise ChainNotExist(f"Chain with entity id {entity_id} not exist")
        
        documentStatus = self.chains.update_one(
            {"entity_id": entity_id},
            {"$set":
                {
                    "federation": {
                        "chain": trust_chain,
                        "exp": exp
                    }
                },
             }
        )
        
        return documentStatus