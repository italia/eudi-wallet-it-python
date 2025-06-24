from typing import Callable
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect, Response
from satosa.attribute_mapping import AttributeMapper
from pyeudiw.tools.utils import iat_now
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.satosa.utils.respcode import ResponseCodeSource
from pyeudiw.tools.base_endpoint import BaseEndpoint
from pyeudiw.satosa.utils.html_template import Jinja2TemplateHandler

class GetResponseHandler(BaseEndpoint):

    def __init__(
            self, 
            config: dict, 
            internal_attributes: dict[str, dict[str, str | list[str]]], 
            base_url: str, 
            name: str,
            auth_callback_func: Callable[[Context, InternalData], Response],
            converter: AttributeMapper
        ) -> None:
        """
        Initialize the GetRequestHandler with the given configuration, internal attributes, base URL, and name.
        
        :param config: Configuration dictionary for the handler.
        :param internal_attributes: Internal attributes mapping.
        :param base_url: Base URL for the handler.
        :param name: Name of the handler.

        :raises ValueError: If storage settings are not configured.
        """
        super().__init__(config, internal_attributes, base_url, name, auth_callback_func, converter)

        self.storage_settings = self.config.get("storage", {})
        if not self.storage_settings:
            raise ValueError(
                "Storage settings are not configured. Please check your configuration."
            )

        # Initialize the database engine
        self.db_engine = DBEngine(self.storage_settings)

        self.response_code_helper = ResponseCodeSource(
            self.config["response_code"]["sym_key"]
        )

        # HTML template loader
        self.template = Jinja2TemplateHandler(self.config["ui"])


    def endpoint(self, context: Context) -> Redirect | Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance after the authorization is done for retrieving the response.

        :type context: the context of current request
        :param context: the request context

        :return: a response containing the response
        :rtype: satosa.response.Response
        """

        self._log_function_debug("get_response_endpoint", context)
        resp_code = (context.qs_params or {}).get("response_code", None)

        if not resp_code:
            return self._handle_400(
                context, 
                "request error: missing or invalid parameter [response_code]"
            )

        session_id = context.state.get("SESSION_ID", None) if context.state else None

        if not session_id:
            return self._handle_400(
                context, 
                "request error: session id not found"
            )

        try:
            state = self.response_code_helper.recover_state(resp_code)
        except Exception as e400:
            return self._handle_400(
                context, 
                "request error: missing or invalid parameter [response_code]",
                e400
            )

        finalized_session = None
        try:
            finalized_session = self.db_engine.get_by_state_and_session_id(
                state=state, session_id=session_id
            )
        except Exception as e401:
            self._log_error(
                context,
                f"Error while retrieving internal response with response_code {resp_code} and session_id {session_id}: {e401}"
            )
            return self._handle_401(
                context, 
                "client error: no session associated to the state",
                e401
            )

        if not finalized_session:
            return self._handle_400(
                context, 
                "request error: session not finalized"
            )

        _now = iat_now()
        _exp = finalized_session["request_object"]["exp"]
        if _exp < _now:
            return self._handle_400(
                context,
                "request error: request expired",
            )

        if finalized_session.get("error_response"):
            return self._get_response_authorization_error_page(finalized_session["error_response"])
        if finalized_session.get("internal_response"):
            return self._get_response_auth_callback(context, finalized_session["internal_response"])

        return self._handle_500(
            context,
            "finished authentication at an invalid state",
            Exception("finished authentication is in an invalid state: neither user data nor error are located in a finished session", finalized_session)
        )
    
    def _get_response_authorization_error_page(self, wallet_error_response: dict) -> Response:
        result = self.template.authorization_error_response_page.render({
            "error": wallet_error_response.get("error"),
            "error_description": wallet_error_response.get("error_description")
        })
        return Response(result, content="text/html; charset=utf8", status="401")

    def _get_response_auth_callback(self, context, internal_resp_data: dict):
        internal_response = InternalData()
        resp = internal_response.from_dict(internal_resp_data)
        if not hasattr(self, "_auth_callback") or self._auth_callback is None:
            raise AttributeError("The '_auth_callback' method is not defined or is None.")
        return self._auth_callback(context, resp)