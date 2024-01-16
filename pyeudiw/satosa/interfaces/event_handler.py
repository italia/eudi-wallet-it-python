from pyeudiw.storage.db_engine import DBEngine
from satosa.backends.base import BackendModule
from pyeudiw.tools.base_logger import BaseLogger
from ..impl.base_http_error_handler import BaseHTTPErrorHandler

class EventHandlerInterface(BackendModule, BaseHTTPErrorHandler, BaseLogger):
    """
    Interface for event handlers.
    """
    
    @property
    def db_engine(self) -> DBEngine:
        """Returns the database engine."""
        raise NotImplementedError
    
    @property
    def default_metadata_private_jwk(self) -> tuple:
        """Returns the default metadata private JWK."""
        raise NotImplementedError
    
    @property
    def server_url(self):
        """Returns the server url."""
        raise NotImplementedError
    
    @property
    def client_id(self) -> str:
        """Returns the client id."""
        raise NotImplementedError