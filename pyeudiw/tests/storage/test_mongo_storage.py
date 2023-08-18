import uuid

import pytest

from pyeudiw.storage.mongo_storage import MongoStorage


class TestMongoStorage:
    @pytest.fixture(autouse=True)
    def create_storage_instance(self):
        self.storage = MongoStorage(
            {
                "db_name": "eudiw",
                "db_sessions_collection": "sessions",
                "db_trust_attestations_collection": "trust_attestations",
                "db_trust_anchors_collection": "trust_anchors"
            },
            "mongodb://localhost:27017/",
            {}
        )

    def test_mongo_connection(self):
        self.storage._connect()

        assert self.storage.db is not None
        assert self.storage.client
        assert self.storage.sessions is not None
        assert self.storage.trust_attestations is not None
        assert self.storage.trust_anchors is not None

    def test_entity_initialization(self):
        state = str(uuid.uuid4())
        session_id = str(uuid.uuid4())

        document_id = self.storage.init_session(
            str(uuid.uuid4()),
            session_id=session_id, state=state)

        assert document_id

        dpop_proof = {"dpop": "test"}
        attestation = {"attestation": "test"}
        self.storage.add_dpop_proof_and_attestation(
            document_id, dpop_proof=dpop_proof, attestation=attestation)

        document = self.storage.get_by_id(document_id)

        assert document
        assert document["dpop_proof"]
        assert document["dpop_proof"] == {"dpop": "test"}
        assert document["attestation"]
        assert document["attestation"] == {"attestation": "test"}

    def test_add_request_object(self):
        state = str(uuid.uuid4())
        session_id = str(uuid.uuid4())

        document_id = self.storage.init_session(
            str(uuid.uuid4()),
            session_id=session_id, state=state)

        assert document_id

        nonce = str(uuid.uuid4())
        request_object = {"nonce": nonce, "state": state}

        self.storage.update_request_object(document_id, request_object)

        document = self.storage.get_by_id(document_id)

        assert document
        assert document["request_object"] == request_object
        assert document["request_object"]["state"]
        assert document["request_object"]["state"] == state
        assert document["request_object"]["state"]
        assert document["request_object"]["nonce"] == nonce

    def test_update_response_object(self):
        state = str(uuid.uuid4())
        session_id = str(uuid.uuid4())

        document_id = self.storage.init_session(
            str(uuid.uuid4()),
            session_id=session_id, state=state)

        assert document_id

        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        request_object = {"nonce": nonce, "state": state}

        self.storage.update_request_object(
            document_id, request_object)
        documentStatus = self.storage.update_response_object(
            nonce, state, {"response": "test"})
        self.storage.add_dpop_proof_and_attestation(
            document_id, dpop_proof={"dpop": "test"}, attestation={"attestation": "test"})
        assert documentStatus

        document = self.storage.get_by_id(document_id)

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
        assert document["internal_response"] == {"response": "test"}
