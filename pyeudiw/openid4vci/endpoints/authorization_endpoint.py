from urllib.parse import parse_qs, urlencode

from pydantic import ValidationError
from satosa.context import Context
from satosa.response import Response, Redirect

from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.models.authorization_request import (
    AuthorizationRequest,
    PAR_REQUEST_URI_CTX,
    CLIENT_ID_CTX
)
from pyeudiw.openid4vci.models.authorization_response import AuthorizationResponse
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    FORM_URLENCODED,
    APPLICATION_JSON
)
from pyeudiw.tools.exceptions import InvalidRequestException
from pyeudiw.tools.session import get_session_id
from pyeudiw.tools.validation import (
    validate_content_type,
    validate_request_method
)


class AuthorizationHandler(BaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the authorization endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)

    def endpoint(self, context: Context) -> Response:
        """
        Handle an authorization request, via GET or POST.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object, usually a redirect.
        """
        global entity
        try:
            entity = self.db_engine.get_by_session_id(get_session_id(context))
            validate_request_method(context.request_method, ["POST", "GET"])
            if context.request_method == "POST":
                validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
                auth_req = self._get_body(context)
            else:
                validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
                auth_req = parse_qs(context.request.qs_params)

            if not auth_req:
                raise InvalidRequestException("missing authorization request")

            AuthorizationRequest.model_validate(
                auth_req, context = {
                    PAR_REQUEST_URI_CTX: self._to_request_uri(entity.request_uri_part),
                    CLIENT_ID_CTX: entity.client_id
                })
            return AuthorizationResponse(
                state=entity.state,
                iss=self.entity_id,
            ).to_redirect_response(entity.redirect_uri)
        except (InvalidRequestException, ValidationError, TypeError) as e:
            return self._to_error_redirect(
                getattr(entity, "redirect_uri", None),
                "invalid_request",
                self._handle_validate_request_error(e, 'authorization'),
                getattr(entity, "state", None))
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke authorization endpoint: {e}"
            )
            return self._to_error_redirect(
                getattr(entity, "redirect_uri", None),
                "server_error",
                "error during invoke authorization endpoint",
                getattr(entity, "state", None))

    @staticmethod
    def _to_error_redirect(url:str, error:str, desc: str, state: str):
        params = {
            "error": error,
            "error_description": desc
        }
        if state is not None:
            params["state"] = state
        return Redirect(
            f"{url}?{urlencode(params)}",
            content = FORM_URLENCODED)