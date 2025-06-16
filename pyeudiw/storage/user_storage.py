import pymongo

from pyeudiw.storage.base_storage import BaseStorage
from pyeudiw.storage.user_entity import UserEntity


class UserStorage(BaseStorage):
    """
    A storage class extending MongoStorage to manage user for OpenID4VCI interactions.

    This class provides methods to initialize, retrieve, and update session data stored in a MongoDB database.
    """

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
            self.users = getattr(
                self.db, self.storage_conf["db_users_collection"]
            )

    def get_by_fiscal_code(self, fiscal_code: str) -> UserEntity:
        return self.get_by_field("fiscal_code",fiscal_code)

    def get_by_field(self, field_name: str, field_value: str) -> UserEntity:
        query = {field_name: field_value}
        return self.get_by_fields(query)

    def get_by_fields(self, query: dict) -> UserEntity:
        self._connect()
        document = self.users.find_one(query)

        if document is None:
            raise ValueError(f"User with {query} not found.")

        return UserEntity(**document)

    def close(self):
        self._connect()
        self.client.close()

    def set_session_retention_ttl(self, ttl: int) -> None:
        self._connect()

        if not ttl:
            if self.users.index_information().get("creation_date_1"):
                self.users.drop_index("creation_date_1")
        else:
            self.users.create_index(
                [("creation_date", pymongo.ASCENDING)], expireAfterSeconds=ttl
            )