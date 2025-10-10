from typing import Callable
from uuid import uuid4

from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response, Redirect

from pyeudiw.satosa.backends.openid4vp.authorization_request import build_authorization_request_url
from pyeudiw.satosa.backends.openid4vp.endpoints.vp_base_endpoint import VPBaseEndpoint
from pyeudiw.satosa.backends.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.satosa.backends.openid4vp.utils import detect_flow_typ
from pyeudiw.satosa.utils.html_template import Jinja2TemplateHandler
from pyeudiw.trust.dynamic import CombinedTrustEvaluator


class PreRequestHandler(VPBaseEndpoint):

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

        self.absolute_request_url = f"{self.client_id}/request-uri"
        self.absolute_status_url = f"{self.client_id}/status"

        self.qrcode_settings: dict[str, str] = self.config.get("qrcode") or {}
        if not self.qrcode_settings:
            raise ValueError(
                "QR code settings are not configured. Please check your configuration."
            )

        # HTML template loader
        self.template = Jinja2TemplateHandler(self.config["ui"])
        
        # This loads all the configured trust evaluation mechanisms
        trust_configuration = self.config.get("trust", {})
        trust_caching_mode = self.config.get("trust_caching_mode", "update_first")
        
        self.trust_evaluator = trust_evaluator
        self.force_same_device_flow_referer_criteria = self.config.get("force_same_device_flow_referer_criteria")
    
    def endpoint(self, context: Context) -> Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance before calling the request endpoint.
        It initializes the session and returns the request_uri to be used by the User-Agent/Wallet Instance.

        :type context: the context of current request
        :param context: the request context
        :type internal_request: satosa.internal.InternalData
        :param internal_request: Information about the authorization request

        :return: a response containing the request_uri
        :rtype: satosa.response.Response
        """

        self._log_function_debug(
            "pre_request_endpoint", context, "internal_request"
        )

        if context.state is None or "SESSION_ID" not in context.state:
            self._log_error(context, "SESSION_ID not found in context.state or context.state is None")
            return self._handle_400(
                context,
                "Session ID not found in request context."
            )
        
        session_id = context.state["SESSION_ID"]
        state = str(uuid4())

        if not context.target_frontend:
            _msg = "Preventing session creation: context is not linked to any previous authn session."
            self._log_warning(context, _msg)
            return self._handle_400(
                context,
                "previous authn session not found. It seems that the flow did "
                "not started with a valid authn request to one of the configured frontend.",
            )

        flow_typ = detect_flow_typ(context, self.force_same_device_flow_referer_criteria)

        # Init session
        try:
            self.db_engine.init_session(
                state=state, session_id=session_id, remote_flow_typ=flow_typ.value
            )
        except Exception as e500:
            self._log_error(
                context, 
                f"Error while initializing session with state {state} and {session_id}: {e500}"
            )
            return self._handle_500(
                context, 
                "internal error: something went wrong when creating your authentication request",
                e500
            )

        qs_params = getattr(context, "qs_params") or {}
        client_id_hint = qs_params.get("client_id_hint", None)
        has_client_id_hint = client_id_hint is not None and self.trust_evaluator.has_client_id(
            client_id_hint
        )

        # PAR
        payload = {
            "client_id": client_id_hint if has_client_id_hint else self.client_id,
            "request_uri": f"{self.absolute_request_url}?id={state}",
        }

        response_url = build_authorization_request_url(
            self.config["authorization"]["url_scheme"], payload
        )

        if flow_typ == RemoteFlowType.SAME_DEVICE:
            return self._same_device_http_response(response_url)
        elif flow_typ == RemoteFlowType.CROSS_DEVICE:
            return self._cross_device_http_response(response_url, state)
        
        return self._handle_400(
            context,
            "Invalid flow type detected. Please check your configuration.",
        )
    
    @staticmethod
    def _same_device_http_response(response_url: str) -> Response:
        return Redirect(response_url)

    def _cross_device_http_response(self, response_url: str, state: str) -> Response:
        result = self.template.qrcode_page.render(
            {
                "qrcode_color": self.qrcode_settings["color"],
                "qrcode_text": response_url,
                "qrcode_size": self.qrcode_settings["size"],
                "qrcode_logo_path": self.qrcode_settings["logo_path"],
                "qrcode_expiration_time": self.qrcode_settings["expiration_time"],
                "state": state,
                "status_endpoint": self.absolute_status_url,
            }
        )
        return Response(result, content="text/html; charset=utf8", status="200")