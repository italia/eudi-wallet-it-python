import pymongo
import logging
from datetime import datetime, timezone

from pyeudiw.exceptions import ValidationError
from pyeudiw.storage.credential_entity import CredentialEntity
from pyeudiw.storage.mongo_storage import MongoStorage
from pyeudiw.storage.exceptions import EntryNotFound

logger = logging.getLogger(__name__)

class CredentialStorage(MongoStorage):
    """
    A storage class extending MongoStorage to manage user credentials for OpenID4VCI interactions.

    This class provides methods to initialize, retrieve, and update session data stored in a MongoDB database.
    """

    #: Identifier of the counter document used to allocate status list indexes.
    _INCREMENTAL_ID_COUNTER = "credential_incremental_id"

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
            self.counters = getattr(
                self.db,
                self.storage_conf.get("db_counters_collection", "credential_counters"),
            )
            # Defense in depth: even if two issuers ever computed the same id,
            # the unique index makes the duplicate insert fail rather than
            # silently corrupting the status list. Creating an index is
            # idempotent, so it is safe to call on every (re)connect.
            self.credentials.create_index("incremental_id", unique=True)

    def get_credential_by_user_id(self, user_id: str) -> CredentialEntity:
        return self.get_by_field("user_id", user_id)

    def get_by_field(self, field_name: str, field_value: str) -> CredentialEntity:
        query = {field_name: field_value}
        return self.get_by_fields(query)

    def get_credential_by_fields(self, **kargs) -> CredentialEntity:
        document = self.credentials.find_one(kargs)
        if not document:
            return None
        return CredentialEntity(**document)

    def get_by_fields(self, query: dict) -> CredentialEntity:
        self._connect()
        document = self.credentials.find_one(query)

        if document is None:
            raise ValueError(f"Credential with {query} not found.")

        return CredentialEntity(**document)

    def count_credential(self) -> CredentialEntity | None:
        self._connect()
        output = self.credentials.find_one(sort=[("incremental_id", -1)])
        return output

    def _next_incremental_id(self) -> int:
        """
        Atomically allocate a unique, monotonically increasing status list index.

        This relies on a single MongoDB ``findAndModify`` (``$inc``) operation,
        which the server guarantees to execute atomically. Unlike a
        read-max-then-increment approach, concurrent issuers can never observe
        the same value, so parallel workers never collide on a status list
        index. The first allocated id is ``1``.

        :return: the freshly allocated incremental id.
        :rtype: int
        """
        counter = self.counters.find_one_and_update(
            {"_id": self._INCREMENTAL_ID_COUNTER},
            {"$inc": {"seq": 1}},
            upsert=True,
            return_document=pymongo.ReturnDocument.AFTER,
        )
        return counter["seq"]

    def add_credential_for_user(self, credential_entity: CredentialEntity) -> int:
        self._connect()
        credential_entity.incremental_id = self._next_incremental_id()
        self.credentials.insert_one(credential_entity.__dict__)
        return credential_entity.incremental_id

    def revoke_credential(self, credential_entity: CredentialEntity) -> CredentialEntity:
        self._connect()
        query = {"document_id": credential_entity.document_id}
        update = {
            "$set": {
                "revoked": True,
                "revocation_date": datetime.now(
                    tz=timezone.utc
                ).timestamp(),
                "update_date": datetime.now(
                    tz=timezone.utc
                ).timestamp(),
            }
        }
        return self.credentials.update_one(query, update)

    def get_all_sorted_by_incremental_id(
        self, sort_direction=pymongo.ASCENDING
    ) -> list[dict]:
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
