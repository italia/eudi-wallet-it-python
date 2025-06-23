from uuid import uuid4
from typing import Callable
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response, Redirect
from satosa.attribute_mapping import AttributeMapper
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.openid4vp.utils import detect_flow_typ
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.satosa.utils.html_template import Jinja2TemplateHandler
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vp.authorization_request import build_authorization_request_url

class PreRequestHandler(BaseEndpoint):

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
        Initialize the AuthorizationHandler with the given configuration, internal attributes, base URL, and name.

        :param config: Configuration dictionary for the handler.
        :param internal_attributes: Internal attributes mapping.
        :param base_url: Base URL for the handler.
        :param name: Name of the handler.

        :raises ValueError: If storage or QR code settings are not configured.
        """

        super().__init__(config, internal_attributes, base_url, name, auth_callback_func, converter)

        if self.config["authorization"].get("client_id"):
            self.client_id = self.config["authorization"]["client_id"] 
        elif self.config["metadata"].get("client_id"):
            self.client_id = self.config["metadata"]["client_id"]
        else:
            self.client_id = f"{base_url}/{name}"

        self.absolute_request_url = f"{self.client_id}/request"
        self.absolute_status_url = f"{self.client_id}/status"

        self.storage_settings = self.config.get("storage", {})
        if not self.storage_settings:
            raise ValueError(
                "Storage settings are not configured. Please check your configuration."
            )

        # Initialize the database engine
        self.db_engine = DBEngine(self.storage_settings)

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
        
        self.trust_evaluator = CombinedTrustEvaluator.from_config(
            trust_configuration, 
            self.db_engine, 
            default_client_id = self.client_id, 
            mode = trust_caching_mode
        )
    
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

        flow_typ = detect_flow_typ(context)

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