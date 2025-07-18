from typing import Callable

from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect, Response

from pyeudiw.satosa.backends.openid4vp.endpoints.vp_base_endpoint import VPBaseEndpoint
from pyeudiw.satosa.utils.respcode import ResponseCodeSource
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.tools.utils import iat_now
from pyeudiw.trust.dynamic import CombinedTrustEvaluator


class StatusHandler(VPBaseEndpoint):

    def __init__(
            self, 
            config: dict, 
            internal_attributes: dict[str, dict[str, str | list[str]]], 
            base_url: str, 
            name: str,
            auth_callback_func: Callable[[Context, InternalData], Response],
            converter: AttributeMapper,
            trust_evaluator: CombinedTrustEvaluator
        ) -> None:
        """
        Initialize the AuthorizationHandler with the given configuration, internal attributes, base URL, and name.

        :param config: Configuration dictionary for the handler.
        :param internal_attributes: Internal attributes mapping.
        :param base_url: Base URL for the handler.
        :param name: Name of the handler.

        :raises ValueError: If storage or QR code settings are not configured.
        """

        super().__init__(config, internal_attributes, base_url, name, auth_callback_func, converter)

        self.registered_get_response_endpoint = f"{self.client_id}/get_response"

        self.response_code_helper = ResponseCodeSource(
            self.config["response_code"]["sym_key"]
        )

    def endpoint(self, context: Context) -> Redirect | Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance to check the status of the request.

        :type context: the context of current request
        :param context: the request context

        :return: a response containing the status of the request
        :rtype: satosa.response.Response
        """

        self._log_function_debug("status_endpoint", context)

        if not context.state or "SESSION_ID" not in context.state:
            return self._handle_400(
                context,
                "request error: missing SESSION_ID in context state",
                ValueError("Missing SESSION_ID in context state")
            )
        session_id = context.state["SESSION_ID"]

        try:
            if not context.qs_params or "id" not in context.qs_params:
                raise ValueError("id")
            
            state = context.qs_params["id"]

            if not state:
                raise ValueError("id")

        except Exception as e400:
            return self._handle_400(
                context, 
                "request error: missing or invalid parameter [id]",
                e400
            )

        try:
            session = self.db_engine.get_by_state_and_session_id(
                state=state, session_id=session_id
            )
        except Exception as e401:
            self._log_error(
                context,
                f"Error while retrieving session by state {state} and session_id {session_id}: {e401}"
            )
            return self._handle_401(
                context,
                "client error: no session associated to the state",
                e401
            )

        if session is None:
            return self._handle_401(
                context,
                "client error: no session found for the given state and session_id",
                Exception("Session is None")
            )

        request_object = session.get("request_object", None)
        if request_object:
            if iat_now() > request_object["exp"]:
                return self._status_session_expired_response(context)

        if session.get("finalized"):
            if session.get("error_response"):
                return self._status_session_finished_error_response(context, session["error_response"])
            return self._status_session_finished_ok_response(state)

        if request_object is not None:
            return self._status_session_accepted_response()

        return self._status_session_created_response()

    def _status_session_expired_response(self, context) -> Response:
        return self._handle_403(
            context,
            "request error: request expired",
        )

    def _status_session_finished_ok_response(self, state: str) -> Response:
        resp_code = self.response_code_helper.create_code(state)
        return JsonResponse(
            {
                "redirect_uri": f"{self.registered_get_response_endpoint}?response_code={resp_code}"
            },
            status="200",
        )

    def _status_session_finished_error_response(self, context, wallet_error: dict) -> Response:
        self._log_error(
            context,
            f"the wallet rejected the authentication attempt and responsed with the following Authorization Response Error: {wallet_error}"
        )
        return JsonResponse(
            {
                "error": "authentication_failed",
                "error_description": "The Wallet Instance or its User have rejected the request, the request is expired, or other errors prevented the authentication."
            },
            status="401"
        )

    def _status_session_accepted_response(self) -> Response:
        return JsonResponse({"response": "Accepted"}, status="202")

    def _status_session_created_response(self) -> Response:
        return JsonResponse({"response": "Request object issued"}, status="201")