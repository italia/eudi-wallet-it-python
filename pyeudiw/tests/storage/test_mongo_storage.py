import uuid
import pytest

from pyeudiw.storage.mongo_storage import MongoStorage


class TestMongoStorage:
    @pytest.fixture(autouse=True)
    def create_storage_instance(self):
        self.storage = MongoStorage(
            {"db_name": "eudiw", "db_collection": "test"},
            "mongodb://localhost:27017/",
            {}
        )

    def test_mongo_connection(self):
        self.storage._connect()

        assert self.storage.db is not None
        assert self.storage.client
        assert self.storage.collection is not None

    def test_entity_initialization(self):
        document_id = self.storage.init_session(
            {"dpop": "test"}, {"attestation": "test"})

        assert document_id

        document = self.storage._retrieve_document_by_id(document_id)

        assert document
        assert document["dpop_proof"]
        assert document["dpop_proof"] == {"dpop": "test"}
        assert document["attestation"]
        assert document["attestation"] == {"attestation": "test"}

    def test_add_request_object(self):
        document_id = self.storage.init_session(
            {"dpop": "test"}, {"attestation": "test"})

        assert document_id

        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        request_object = {"nonce": nonce, "state": state}

        self.storage.update_request_object(document_id, request_object)

        document = self.storage._retrieve_document_by_id(document_id)

        assert document
        assert document["dpop_proof"]
        assert document["dpop_proof"] == {"dpop": "test"}
        assert document["attestation"]
        assert document["attestation"] == {"attestation": "test"}
        assert document["state"]
        assert document["state"] == state
        assert document["state"]
        assert document["nonce"] == nonce
        assert document["request_object"] == request_object

    def test_update_responnse_object(self):
        document_id = self.storage.init_session(
            {"dpop": "test"}, {"attestation": "test"})

        assert document_id

        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        request_object = {"nonce": nonce, "state": state}

        self.storage.update_request_object(document_id, request_object)
        documentStatus = self.storage.update_response_object(
            nonce, state, {"response": "test"})

        assert documentStatus

        document = self.storage._retrieve_document_by_id(document_id)

        assert document
        assert document["dpop_proof"]
        assert document["dpop_proof"] == {"dpop": "test"}
        assert document["attestation"]
        assert document["attestation"] == {"attestation": "test"}
        assert document["state"]
        assert document["state"] == state
        assert document["state"]
        assert document["nonce"] == nonce
        assert document["request_object"] == request_object
        assert document["response_object"]
        assert document["response_object"] == {"response": "test"}
