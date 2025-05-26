import pymongo

from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from pyeudiw.openid4vci.storage.storage_interface import StorageInterface


class MongoStorage(StorageInterface):
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
            self.client = pymongo.MongoClient(self.url, **self.connection_params)
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

    def init_session(self, entity: OpenId4VCIEntity) -> str:
        self._connect()
        self.sessions.insert_one(entity)
        return entity.document_id

    def get_by_session_id(self, session_id: str = "") -> OpenId4VCIEntity:
        self._connect()
        query = {"session_id": session_id}
        document = self.sessions.find_one(query)

        if document is None:
            raise ValueError(f"Document with session_id {session_id} not found.")

        return OpenId4VCIEntity(**document)
