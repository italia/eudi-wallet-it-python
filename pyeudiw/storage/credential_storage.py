import pymongo

from pyeudiw.storage.credential_entity import CredentialEntity
from pyeudiw.storage.mongo_storage import MongoStorage


class CredentialStorage(MongoStorage):
    """
    A storage class extending MongoStorage to manage user credentials for OpenID4VCI interactions.

    This class provides methods to initialize, retrieve, and update session data stored in a MongoDB database.
    """
    def __init__(self, conf: dict, url: str, connection_params=None) -> None:
        if connection_params is None:
            connection_params = {}
        super().__init__(conf, url, connection_params)

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
            self.credentials = getattr(
                self.db, self.storage_conf["db_credentials_collection"]
            )

    def get_credential_by_user_id(self, user_id: str) -> CredentialEntity:
        return self.get_by_field("user_id", user_id)

    def get_by_field(self, field_name: str, field_value: str) -> CredentialEntity:
        query = {field_name: field_value}
        return self.get_by_fields(query)

    def get_by_fields(self, query: dict) -> CredentialEntity:
        self._connect()
        document = self.credentials.find_one(query)

        if document is None:
            raise ValueError(f"Credential with {query} not found.")

        return CredentialEntity(**document)

    def get_all_sorted_by_incremental_id(self, sort_direction = pymongo.ASCENDING) -> list[dict]:
        self._connect()
        return list(self.credentials.find().sort("incremental_id", sort_direction))

    def close(self):
        self._connect()
        self.client.close()

    def set_session_retention_ttl(self, ttl: int) -> None:
        self._connect()

        if not ttl:
            if self.credentials.index_information().get("creation_date_1"):
                self.credentials.drop_index("creation_date_1")
        else:
            self.credentials.create_index(
                [("creation_date", pymongo.ASCENDING)], expireAfterSeconds=ttl
            )