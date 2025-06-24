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
from pyeudiw.tools.base_endpoint import BaseEndpoint

REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri"

class VCIBaseEndpoint(BaseEndpoint):

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
        super().__init__(config, internal_attributes, base_url, name, auth_callback, converter)
        self.config_utils = Openid4VciFrontendConfigUtils(config)
        self._validate_configs()

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
        return f"{REQUEST_URI_PREFIX}:{random_part}"

    @staticmethod
    def _get_body(context: Context):
        """
          Retrieve body from the HTTP request.
        """
        if not context.request or context.request == '{}':
            return None
        if isinstance(context.request, dict) or isinstance(context.request, set):
            return context.request
        try: parsed = json.loads(context.request)
        except (json.JSONDecodeError, TypeError): parsed = context.request
        return parsed

    @property
    def entity_id(self) -> str:
        if _cid := self.config_utils.get_openid_credential_issuer().credential_issuer:
            return _cid
        else:
            return self._backend_url
