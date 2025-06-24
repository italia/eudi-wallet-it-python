import json
import re
from typing import Any, Callable

from pydantic import ValidationError
from satosa.context import Context
from satosa.response import (
    Redirect,
    Response
)
from satosa.attribute_mapping import AttributeMapper

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.openid4vci.tools.config import Openid4VciFrontendConfigUtils
from pyeudiw.openid4vci.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.satosa.utils.base_http_response_handler import BaseHTTPResponseHandler
from pyeudiw.tools.base_logger import BaseLogger

REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri"

class BaseEndpoint(BaseHTTPResponseHandler, BaseLogger):

    def __init__(
            self, 
            config: dict, 
            internal_attributes: dict[str, dict[str, str | list[str]]], 
            base_url: str, 
            name: str, 
            auth_callback: Callable[[Context, Any], Response] | None = None,
            converter: AttributeMapper | None = None):
        """
        Initialize the OpenID4VCI endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
            auth_callback (Callable, optional): A callback function to handle authorization requests. Defaults to None.
        """
        self.config = config
        self.internal_attributes = internal_attributes
        self._auth_callback = auth_callback
        self._converter = converter
        self._backend_url = f"{base_url}/{name}"

    def __call__(self, context: Context) -> Redirect | Response:
        return self.endpoint(context)

    def _validate_configs(self):
        """
        Hook method to be optionally overridden by subclasses for endpoint-specific config validation.
        """
        pass  # Default no-op. Subclasses should override if needed.

    @staticmethod
    def _validate_required_configs(fields: list[tuple[str, Any]]):
        """
        Validates that the given configuration fields are non-empty.

        Args:
            fields (list of tuple): A list of (field_name, field_value) pairs to validate.

        Raises:
            ValueError: If any field is None or falsy.
        """
        missing_fields = [name for name, value in fields if not value]
        if missing_fields:
            raise ValueError(
                f"The following configuration fields must be provided and non-empty: {', '.join(missing_fields)}"
            )

    def endpoint(self, context: Context) -> Redirect | Response:
        """
        Handle the incoming request and return either a Redirect or Response.

        This method must be implemented by subclasses to process the given context
        and return an appropriate HTTP response, such as a redirect to another
        URL or a standard HTTP response.

        Args:
            context (Context): The SATOSA context object containing the request and environment information.

        Returns:
            Redirect | Response: A Redirect or Response object depending on the logic implemented.

        Raises:
            NotImplementedError: If the method is not overridden by a subclass.
        """
        raise NotImplementedError
