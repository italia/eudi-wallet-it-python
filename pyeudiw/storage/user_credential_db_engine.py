from pyeudiw.storage.credential_storage import CredentialStorage
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.user_storage import UserStorage

class UserCredentialEngine:
    """
        Engine for managing User and Credential storage operations.

        This class provides a wrapper around the configured storage backend,
        typically a MongoDB-based engine, used for persisting and retrieving
        user and credential related data. It lazily initializes the DB engine and ensures
        it is connected when accessed.

        Attributes:
            _storage (str): The name or URI of the configured storage backend,
                typically loaded from self.config["storage"].
            _db_user_engine (UserStorage | None): The lazily initialized instance
                of the storage engine.
            _db_credential_engine (CredentialStorage | None): The lazily initialized instance
                of the storage engine.
    """

    def __init__(self, config: dict):
        self.config = config
        self._db_user_engine = None
        self._db_credential_engine = None


    @property
    def db_user_storage_engine(self) -> UserStorage:
        """
        Lazily initialized access to MongoDB storage engine.
        Returns:q
            MongoStorage: The initialized DB engine instance.
        """
        user_storage_config = self.config["user_storage"]
        if not self._db_user_engine:
            self._db_user_engine = DBEngine(user_storage_config)

        try:
            self._db_user_engine.is_connected
        except Exception as e:
            if getattr(self, "_db_engine", None):
                self._log_error(
                    e.__class__.__name__,
                    f"db user_storage handling, connection check silently fails and get restored: {e}"
                )
            self._db_user_engine = DBEngine(user_storage_config)

        return self._db_user_engine


    @property
    def db_credential_storage_engine(self) -> CredentialStorage:
        """
        Lazily initialized access to MongoDB storage engine.
        Returns:q
            MongoStorage: The initialized DB engine instance.
        """
        credential_storage_config = self.config["credential_storage"]
        if not self._db_credential_engine:
            self._db_credential_engine = DBEngine(credential_storage_config)

        try:
            self._db_credential_engine.is_connected
        except Exception as e:
            if getattr(self, "_db_engine", None):
                self._log_error(
                    e.__class__.__name__,
                    f"db credential_storage handling, connection check silently fails and get restored: {e}"
                )
            self._db_credential_engine = DBEngine(credential_storage_config)

        return self._db_user_engine