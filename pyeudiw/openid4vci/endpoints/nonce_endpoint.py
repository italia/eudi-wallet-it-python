from uuid import uuid4

from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.models.nonce_response import NonceResponse
from pyeudiw.openid4vci.storage.openid4vci_engine import OpenId4VciEngine
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON
)
from pyeudiw.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.tools.session import get_session_id
from pyeudiw.tools.validation import (
    validate_content_type,
    validate_request_method
)


class NonceHandler(BaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the nonce endpoint class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])
        self.db_engine = OpenId4VciEngine.db_engine

    def endpoint(self, context: Context) -> Response:
        """
        Handle a POST request to the nonce endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            if self._get_body(context):
                return self._handle_400(context, "Request body must be empty for nonce endpoint")
            c_nonce = str(uuid4())
            self.db_engine.update_nonce_by_session_id(get_session_id(context), c_nonce)
            return NonceResponse.to_response(c_nonce)
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke nonce endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke nonce endpoint", e)