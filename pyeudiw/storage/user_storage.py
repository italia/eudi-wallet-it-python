import pymongo

from pyeudiw.storage.mongo_storage import MongoStorage
from pyeudiw.storage.user_entity import UserEntity


class UserStorage(MongoStorage):
    """
    A storage class extending MongoStorage to manage user for OpenID4VCI interactions.

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
            self.users = getattr(
                self.db, self.storage_conf["db_users_collection"]
            )

    def get_by_fiscal_code(self, fiscal_code: str) -> tuple[str, UserEntity]:
        return self.get_by_field("fiscal_code",fiscal_code)

    def get_by_field(self, field_name: str, field_value: str) -> tuple[str, UserEntity]:
        query = {field_name: field_value}
        return self.get_by_fields(query)

    def get_by_fields(self, query: dict) -> tuple[str, UserEntity]:
        self._connect()
        document = self.users.find_one(query)

        if document is None:
            raise ValueError(f"User with {query} not found.")

        return str(document.get("_id")), UserEntity(**document)

    def upsert_user(self, user_entity: UserEntity | dict) -> str:
        entity = user_entity if isinstance(user_entity, dict) else vars(user_entity)
        self._connect()
        fiscal_code_query = {"fiscal_code": entity["fiscal_code"]}
        result = self.users.update_one(fiscal_code_query, {"$set": entity}, upsert=True)
        return result.upserted_id if result.upserted_id is not None else (self.users.find_one(fiscal_code_query, {"_id": 1}) or {}).get("_id")

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