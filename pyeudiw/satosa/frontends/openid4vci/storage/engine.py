from pyeudiw.satosa.frontends.openid4vci.storage.openid4vci_storage import OpenId4VciStorage
from pyeudiw.storage.db_engine import DBEngine

class OpenId4VciEngine:
    """
        Engine for managing OpenID4VCI storage operations.

        This class provides a wrapper around the configured storage backend,
        typically a MongoDB-based engine, used for persisting and retrieving
        OpenID4VCI-related data. It lazily initializes the DB engine and ensures
        it is connected when accessed.

        Attributes:
            _storage (str): The name or URI of the configured storage backend,
                typically loaded from self.config["storage"].
            _db_engine (OpenId4VciStorage | None): The lazily initialized instance
                of the storage engine.
    """

    def __init__(self, config: dict):
        self._storage = config["storage"]
        self._db_engine = None

    @property
    def db_engine(self) -> OpenId4VciStorage:
        """
        Lazily initialized access to MongoDB storage engine.
        Returns:
            MongoStorage: The initialized DB engine instance.
        """
        if not self._db_engine:
            self._db_engine = DBEngine(self._storage)

        try:
            self._db_engine.is_connected
        except Exception as e:
            if getattr(self, "_db_engine", None):
                self._log_error(
                    e.__class__.__name__,
                    f"OpenID4VCI db storage handling, connection check silently fails and get restored: {e}"
                )
            self._db_engine = DBEngine(self._storage)

        return self._db_engine