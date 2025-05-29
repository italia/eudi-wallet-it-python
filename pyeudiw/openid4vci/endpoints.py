import logging
from typing import Type

from satosa.context import Context
from satosa.response import (
    BadRequest,
    ServiceError
)

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.models.notification_request import NotificationRequest
from pyeudiw.openid4vci.storage.mongo_storage import MongoStorage
from pyeudiw.openid4vci.utils.config import Config
from pyeudiw.openid4vci.utils.response import (
    ResponseUtils,
    NoContent
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON
)
from pyeudiw.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.tools.validation import (
    validate_content_type,
    validate_request_method
)

logger = logging.getLogger(__name__)

class Openid4VCIEndpoints:
    """
    Class that handles OpenID4VCI endpoints for credential issuance.

    This class manages all incoming requests related to:
    - Credential Offer
    - Pushed Authorization
    - Authorization
    - Token issuance
    - Nonce generation
    - Credential issuance
    - Deferred credential
    - Notification

    Attributes:
        config (dict): Configuration dictionary.
        config_utils (Config): Utility wrapper for config access.
        _db_engine (MongoStorage): Storage backend, initialized lazily.
        _backend_url (str): Full base URL for all endpoints.
        jws_helper (JWSHelper): Utility for verifying and decoding JWS tokens.
    """

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
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])

    def notification_endpoint(self, context: Context) -> Type[NoContent] | BadRequest | ServiceError:
        """
        Handle a POST request to the notification endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            NotificationRequest.model_validate(**context.request.body.decode("utf-8"))
            return NoContent
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke notification endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke notification endpoint")

    #def status_assertion_endpoint(self, context: satosa.context.Context)
    #def revocation_endpoint(self, context: satosa.context.Context)

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
                logger.error(
                    f"OpenID4VCI db storage handling, connection check silently fails and get restored: {e}",
                )
            self._db_engine = MongoStorage(self.config["storage"])

        return self._db_engine

    @property
    def entity_id(self) -> str:
        if _cid := self.config_utils.get_openid_credential_issuer().credential_issuer:
            return _cid
        else:
            return self._backend_url
