import uuid
import pytest

from pyeudiw.storage.db_engine import DBEngine

conf = {
    "mongo_db": {
        "cache": {
            "module": "pyeudiw.storage.mongo_cache",
            "class": "MongoCache",
            "init_params": {
                "url": "mongodb://localhost:27017/",
                "conf": {
                    "db_name": "eudiw"
                },
                "connection_params": {}
            }
        },
        "storage": {
            "module": "pyeudiw.storage.mongo_storage",
            "class": "MongoStorage",
            "init_params": {
                "url": "mongodb://localhost:27017/",
                "conf": {
                    "db_name": "eudiw",
                    "db_sessions_collection": "sessions",
                    "db_trust_attestations_collection": "trust_attestations",
                    "db_trust_anchors_collection": "trust_anchors"
                },
                "connection_params": {}
            }
        }
    }
}


class TestMongoDBEngine:
    @pytest.fixture(autouse=True)
    def create_engine_instance(self):
        self.engine = DBEngine(conf)

    @pytest.fixture(autouse=True)
    def test_init_session(self):
        state = str(uuid.uuid4())
        session_id = str(uuid.uuid4())

        document_id = self.engine.init_session(
            session_id=session_id, state=state)

        assert document_id

        self.document_id = document_id

    @pytest.fixture(autouse=True)
    def test_update_request_object(self):
        self.nonce = str(uuid.uuid4())
        self.state = str(uuid.uuid4())
        request_object = {"request_object": "request_object",
                          "nonce": self.nonce, "state": self.state}

        replica_count = self.engine.update_request_object(
            self.document_id, request_object)

        assert replica_count == 1

    def test_update_request_object_with_unexistent_id_object(self):
        str(uuid.uuid4())
        str(uuid.uuid4())
        unx_document_id = str(uuid.uuid4())
        request_object = {"request_object": "request_object"}

        try:
            self.engine.update_request_object(
                unx_document_id, request_object)
        except:
            return

    def test_update_response_object(self):
        response_object = {"response_object": "response_object"}
        self.engine.update_response_object(
            self.nonce, self.state, response_object)

    def test_update_response_object_unexistent_id_object(self):
        response_object = {"response_object": "response_object"}

        try:
            replica_count = self.engine.update_response_object(
                str(uuid.uuid4()), str(uuid.uuid4()), response_object)
        except:
            return
