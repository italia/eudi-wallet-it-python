import uuid
import pytest

from datetime import datetime
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.base_storage import TrustType
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.tests.settings import CONFIG


class TestMongoDBEngine:
    @pytest.fixture(autouse=True)
    def create_engine_instance(self):
        self.engine = DBEngine(CONFIG['storage'])

    @pytest.fixture(autouse=True)
    def test_init_session(self):
        state = str(uuid.uuid4())
        session_id = str(uuid.uuid4())

        document_id = self.engine.init_session(
            session_id=session_id, state=state, remote_flow_typ="")

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
        except Exception:
            return

    def test_update_response_object(self):
        response_object = {"response_object": "response_object"}
        self.engine.update_response_object(
            self.nonce, self.state, response_object)

    def test_update_response_object_unexistent_id_object(self):
        response_object = {"response_object": "response_object"}
        try:
            self.engine.update_response_object(
                str(uuid.uuid4()), str(uuid.uuid4()), response_object)
        except Exception:
            return

    @pytest.fixture(autouse=True)
    def test_insert_trusted_attestation_federation(self):
        self.federation_entity_id = str(uuid.uuid4())
        date = datetime.now()

        replica_count = self.engine.add_trust_attestation(
            self.federation_entity_id, ["a", "b", "c"], date)

        assert replica_count > 0

        ta = self.engine.get_trust_attestation(self.federation_entity_id)

        assert ta.get("federation", None) is not None
        assert ta["federation"]["chain"] == ["a", "b", "c"]

    @pytest.fixture(autouse=True)
    def test_insert_trusted_attestation_x509(self):
        self.x509_entity_id = str(uuid.uuid4())
        date = datetime.now()

        replica_count = self.engine.add_trust_attestation(
            self.x509_entity_id, ["a", "b", "c"], date, TrustType.X509)

        assert replica_count > 0

        ta = self.engine.get_trust_attestation(self.x509_entity_id)

        assert ta.get("x509", None) is not None
        assert ta["x509"]["x5c"] == ["a", "b", "c"]

    def test_update_trusted_attestation_federation(self):
        date = datetime.now()

        replica_count = self.engine.update_trust_attestation(
            self.federation_entity_id, ["a", "b", "d"], date)

        assert replica_count > 0

        ta = self.engine.get_trust_attestation(self.federation_entity_id)

        assert ta.get("federation", None) is not None
        assert ta["federation"]["chain"] == ["a", "b", "d"]

    def test_update_trusted_attestation_x509(self):
        date = datetime.now()

        replica_count = self.engine.update_trust_attestation(
            self.x509_entity_id, ["a", "b", "d"], date, TrustType.X509)

        assert replica_count > 0

        ta = self.engine.get_trust_attestation(self.x509_entity_id)

        assert ta.get("x509", None) is not None
        assert ta["x509"]["x5c"] == ["a", "b", "d"]

    def test_update_unexistent_trusted_attestation(self):
        try:
            date = datetime.now()

            self.engine.update_trust_attestation(
                "12345", ["a", "b", "d"], date)

            assert False

        except StorageWriteError:
            return

    def test_update_trusted_attestation_metadata(self):
        replica_count = self.engine.add_trust_attestation_metadata(
            self.federation_entity_id, "test_metadata", {"metadata": {"data_type": "test"}})

        assert replica_count > 0

        ta = self.engine.get_trust_attestation(self.federation_entity_id)

        assert ta.get("metadata", None) is not None
        assert ta["metadata"]["test_metadata"] == {
            "metadata": {"data_type": "test"}}

    def test_update_unexistent_trusted_attestation_metadata(self):
        try:
            self.engine.add_trust_attestation_metadata(
                "test", "test_metadata", {"metadata": {"data_type": "test"}})
            assert False
        except StorageWriteError:
            return

    @pytest.fixture(autouse=True)
    def test_insert_trusted_anchor_federation(self):
        self.federation_entity_anchor_id = str(uuid.uuid4())
        date = datetime.now()

        replica_count = self.engine.add_trust_anchor(
            self.federation_entity_anchor_id, "test123", date)

        assert replica_count > 0

        ta = self.engine.get_trust_anchor(self.federation_entity_anchor_id)

        assert ta.get("federation", None) is not None
        assert ta["federation"]["entity_configuration"] == "test123"

    @pytest.fixture(autouse=True)
    def test_insert_trusted_anchor_x509(self):
        self.x509_entity_anchor_id = str(uuid.uuid4())
        date = datetime.now()

        replica_count = self.engine.add_trust_anchor(
            self.x509_entity_anchor_id, "test123", date, TrustType.X509)

        assert replica_count > 0

        ta = self.engine.get_trust_anchor(self.x509_entity_anchor_id)

        assert ta.get("x509", None) is not None
        assert ta["x509"]["pem"] == "test123"

    def test_update_trusted_anchor_federation(self):
        date = datetime.now()

        replica_count = self.engine.update_trust_anchor(
            self.federation_entity_anchor_id, "test124", date)

        assert replica_count > 0

        ta = self.engine.get_trust_anchor(self.federation_entity_anchor_id)

        assert ta.get("federation", None) is not None
        assert ta["federation"]["entity_configuration"] == "test124"

    def test_update_trusted_anchor_x509(self):
        date = datetime.now()

        replica_count = self.engine.update_trust_anchor(
            self.x509_entity_anchor_id, "test124", date, TrustType.X509)

        assert replica_count > 0

        ta = self.engine.get_trust_anchor(self.x509_entity_anchor_id)

        assert ta.get("x509", None) is not None
        assert ta["x509"]["pem"] == "test124"

    def test_update_unexistent_trusted_anchor(self):
        try:
            date = datetime.now()

            self.engine.update_trust_anchor(
                "12345", "test124", date, TrustType.X509)

            assert False

        except StorageWriteError:
            return
