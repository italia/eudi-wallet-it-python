from satosa.context import Context

from build.lib.pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.openid4vci.storage.mongo_storage import MongoStorage
from pyeudiw.openid4vci.utils.config import Config
from pyeudiw.satosa.utils.base_http_error_handler import BaseHTTPErrorHandler


class BaseEndpoint(BaseLogger, BaseHTTPErrorHandler):

    def __init__(self, config: dict, base_url: str, name: str):
        """
        Initialize the OpenID4VCI endpoints class.
        Args:
            config (dict): The configuration dictionary.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        self.config = config
        self.config_utils = Config(**config)
        self._db_engine = None
        self._backend_url = f"{base_url}/{name}"

    @staticmethod
    def _to_request_uri(random_part: str) -> str:
        """
        Generate the full `request_uri` from a random component.
        Args:
            random_part (str): The unique identifier to include in the URI.
        Returns:
            str: A full URN request_uri string.
        """
        return f"urn:ietf:params:oauth:request_uri:{random_part}"

    @staticmethod
    def _get_session_id(context: Context) -> str:
        """
        Extract the session ID from the SATOSA context.
        Args:
            context (Context): The SATOSA context.
        Returns:
            str: The session ID.
        """
        return context.state["SESSION_ID"]

    @property
    def db_engine(self) -> MongoStorage:
        """
        Lazily initialized access to MongoDB storage engine.
        Returns:
            MongoStorage: The initialized DB engine instance.
        """
        if not self._db_engine:
            self._db_engine = MongoStorage(self.config["storage"])

        try:
            self._db_engine.is_connected
        except Exception as e:
            if getattr(self, "_db_engine", None):
                self._log_error(
                    e.__class__.__name__,
                    f"OpenID4VCI db storage handling, connection check silently fails and get restored: {e}"
                )
            self._db_engine = MongoStorage(self.config["storage"])

        return self._db_engine

    @property
    def entity_id(self) -> str:
        if _cid := self.config_utils.get_openid_credential_issuer().credential_issuer:
            return _cid
        else:
            return self._backend_url