import json
from urllib.parse import urlencode

from satosa.response import BadRequest, Unauthorized, Redirect, ServiceError, Response

from pyeudiw.openid4vci.utils.content_type import APPLICATION_JSON, \
    FORM_URLENCODED


class ResponseUtils:
    """
    Utility class for building standard OAuth2 and OpenID4VCI error responses
    used in SATOSA flows. Supports both direct (JSON) responses and redirects.
    """

    @staticmethod
    def to_invalid_scope_resp(desc: str) -> BadRequest:
        """
        Constructs a BadRequest response with an 'invalid_scope' error.
        Args:
            desc (str): Error description.
        Returns:
            BadRequest: SATOSA BadRequest response.
        """
        return BadRequest(
            json.dumps({"error": "invalid_scope", "error_description": desc}),
            content = APPLICATION_JSON
        )

    @staticmethod
    def to_invalid_request_resp(desc: str) -> BadRequest:
        """
        Constructs a BadRequest response with an 'invalid_request' error.
        Args:
            desc (str): Error description.
        Returns:
            BadRequest: SATOSA BadRequest response.
        """
        return BadRequest(
            json.dumps({"error": "invalid_request", "error_description": desc}),
            content = APPLICATION_JSON
        )

    @staticmethod
    def to_invalid_client_resp(desc: str) -> Unauthorized:
        """
        Constructs an Unauthorized response with an 'invalid_client' error.
        Args:
            desc (str): Error description.
        Returns:
            Unauthorized: SATOSA Unauthorized response.
        """
        return Unauthorized(
            json.dumps({"error": "invalid_client", "error_description": desc}),
            content = APPLICATION_JSON
        )

    @staticmethod
    def to_server_error_resp(desc: str) -> ServiceError:
        """
        Constructs a ServiceError response with a 'server_error' error.
        Args:
            desc (str): Error description.
        Returns:
            ServiceError: SATOSA ServiceError response.
        """
        return ServiceError(
            json.dumps({"error": "server_error", "error_description": desc}),
            content = APPLICATION_JSON
        )

    @staticmethod
    def to_invalid_request_redirect(url: str, desc: str, state: str) -> Redirect:
        """
        Constructs a Redirect response with an 'invalid_request' error and state.
        Args:
            url (str): Redirect target.
            desc (str): Error description.
            state (str): OAuth2 state parameter.
        Returns:
            Redirect: SATOSA Redirect response with form URL encoding.
        """
        params = ResponseUtils._error_redirect("invalid_request", desc, state)
        return Redirect(
            f"{url}?{urlencode(params)}",
            content = FORM_URLENCODED
        )

    @staticmethod
    def to_server_error_redirect(url: str, desc: str, state: str | None = None) -> Redirect:
        """
        Constructs a Redirect response with a 'server_error' error.
        Args:
            url (str): Redirect target.
            desc (str): Error description.
            state (Optional[str]): OAuth2 state parameter (optional).
        Returns:
            Redirect: SATOSA Redirect response with form URL encoding.
        """
        params = ResponseUtils._error_redirect("server_error", desc, state)
        return Redirect(
            f"{url}?{urlencode(params)}",
            content = FORM_URLENCODED
        )

    @staticmethod
    def _error_redirect(error:str, desc: str, state: str):
        params = {
            "error": error,
            "error_description": desc
        }
        if state is not None:
            params["state"] = state
        return params

class NoContent(Response):
    _status = "204 No Content"
