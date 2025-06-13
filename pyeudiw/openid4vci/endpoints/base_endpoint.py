import json
import re

from pydantic import ValidationError
from satosa.context import Context
from satosa.response import (
    Redirect,
    Response
)

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.openid4vci.storage.openid4vci_engine import OpenId4VciEngine
from pyeudiw.satosa.utils.base_http_response_handler import BaseHTTPResponseHandler
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.tools.pyeudiw_frontend_config import PyeudiwFrontendConfigUtils


class BaseEndpoint(BaseHTTPResponseHandler, BaseLogger):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the OpenID4VCI endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        self.config = config
        self.config_utils = PyeudiwFrontendConfigUtils(config)
        self.internal_attributes = internal_attributes
        self.db_engine = OpenId4VciEngine.db_engine
        self._backend_url = f"{base_url}/{name}"

    def _handle_validate_request_error(self, e: Exception, endpoint_name: str):
        if isinstance(e, InvalidRequestException) or isinstance(e, InvalidScopeException):
            return e.message
        elif isinstance(e, JWSVerificationError):
            self._log_error(
                e.__class__.__name__,
                f"{str(e)} in`{endpoint_name}` endpoint"
            )
            return "Not a valid JWS format"
        elif isinstance(e, TypeError):
            match = re.search(r"got an unexpected keyword argument '([^']+)'", str(e))
            if match:
                parameter_name = match.group(1)
                self._log_error(
                    e.__class__.__name__,
                    f"missing {parameter_name} in request `{endpoint_name}` endpoint"
                )
                return f"missing `{parameter_name}` parameter"
            else:
                return "invalid request"
        elif isinstance(e, ValidationError):
            errors = e.errors()
            for err in errors:
                parameter_name = err['loc'][0]
                self._log_error(
                    e.__class__.__name__,
                    f"invalid {parameter_name} in request `{endpoint_name}` endpoint"
                )
                return f"invalid `{parameter_name}` parameter"
            return "invalid request"
        else:
            raise e

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
    def _get_body(context: Context):
        """
          Retrieve body from the HTTP request.
        """
        if not context.request or context.request == '{}':
            return None
        if isinstance(context.request, dict):
            return context.request
        return json.loads(context.request)

    @property
    def entity_id(self) -> str:
        if _cid := self.config_utils.get_openid_credential_issuer().credential_issuer:
            return _cid
        else:
            return self._backend_url

    def __call__(self, context: Context) -> Redirect | Response:
        return self.endpoint(context)

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
