import uuid
from typing import Callable

import pydantic
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect, Response

from pyeudiw.jwk import JWK
from pyeudiw.openid4vp.authorization_request import build_authorization_request_url
from pyeudiw.openid4vp.presentation_submission import PresentationSubmissionHandler
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.openid4vp.utils import detect_flow_typ
from pyeudiw.satosa.interfaces.openid4vp_backend import OpenID4VPBackendInterface
from pyeudiw.satosa.schemas.config import PyeudiwBackendConfig
from pyeudiw.satosa.utils.html_template import Jinja2TemplateHandler
from pyeudiw.satosa.utils.respcode import ResponseCodeSource
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import iat_now
from pyeudiw.trust.anchors_loader import AnchorsLoader
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.trust.handler.interface import TrustHandlerInterface


class OpenID4VPBackend(OpenID4VPBackendInterface, BaseLogger):
    def __init__(
        self,
        auth_callback_func: Callable[[Context, InternalData], Response],
        internal_attributes: dict[str, dict[str, str | list[str]]],
        config: dict[str, dict[str, str] | list[str]],
        base_url: str,
        name: str,
    ) -> None:
        """
        OpenID4VP backend module.
        :param auth_callback_func: Callback should be called by the module after the authorization
        in the backend is done.
        :type auth_callback_func: Callable[[Context, InternalData], Response]
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :type internal_attributes: dict[str, dict[str, str | list[str]]]
        :param config: Configuration parameters for the module.
        :type config: dict[str, dict[str, str] | list[str]]
        :param base_url: base url of the service
        :type base_url: str
        :param name: name of the plugin
        :type name: str
        """
        super().__init__(auth_callback_func, internal_attributes, base_url, name)

        # to be inizialized by .db_engine() property
        self._db_engine = None

        self.config = config

        self._backend_url = f"{base_url}/{name}"
        self._client_id = self._backend_url
        self.config["metadata"]["client_id"] = self.client_id

        self.config["metadata"]["response_uris"] = []
        self.config["metadata"]["response_uris"].append(
            f"{self._backend_url}/response-uri"
        )

        self.config["metadata"]["request_uris"] = []
        self.config["metadata"]["request_uris"].append(
            f"{self._backend_url}/request-uri"
        )

        self.default_exp = int(self.config["jwt"]["default_exp"])

        self.metadata_jwks_by_kids = {i["kid"]: i for i in self.config["metadata_jwks"]}
        self.config["metadata"]["jwks"] = {
            "keys": [JWK(i).public_key for i in self.config["metadata_jwks"]]
        }

        # HTML template loader
        self.template = Jinja2TemplateHandler(self.config["ui"])

        # it will be filled by .register_endpoints
        self.absolute_response_url = None
        self.absolute_request_url = None
        self.absolute_status_url = None
        self.registered_get_response_endpoint = None

        self._server_url = (
            self.base_url[:-1] if self.base_url[-1] == "/" else self.base_url
        )

        try:
            PyeudiwBackendConfig(**config)
        except pydantic.ValidationError as e:
            debug_message = f"""The backend configuration presents the following validation issues: {e}"""
            self._log_warning("OpenID4VPBackend", debug_message)

        self.response_code_helper = ResponseCodeSource(
            self.config["response_code"]["sym_key"]
        )

        # This loads all the configured trust evaluation mechanisms
        trust_configuration = self.config.get("trust", {})
        trust_caching_mode = self.config.get("trust_caching_mode", "update_first")

        AnchorsLoader.load_anchors(
            self.db_engine, config.get("trust_anchors", [])
        )
        
        self.trust_evaluator = CombinedTrustEvaluator.from_config(
            trust_configuration, self.db_engine, default_client_id = self.client_id, mode = trust_caching_mode
        )
        self.vp_token_parser = PresentationSubmissionHandler(
            self.load_credential_presentation_handlers()
        )

    def get_trust_backend_by_class_name(self, class_name: str) -> TrustHandlerInterface:

        for i in self.trust_evaluator.handlers:
            if i.__class__.__name__ == class_name:
                return i

    @property
    def client_id(self):
        if _cid := self.config["authorization"].get("client_id"):
            return _cid
        elif _cid := self.config["metadata"].get("client_id"):
            return _cid
        else:
            return self._client_id

    def register_endpoints(self) -> list[tuple[str, Callable[[Context], Response]]]:
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.

        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        # This loads the metadata endpoints required by the supported/configured trust evaluation methods
        url_map = self.trust_evaluator.build_metadata_endpoints(
            self.name, self._backend_url
        )

        for k, v in self.config["endpoints"].items():
            endpoint_value = v

            if isinstance(endpoint_value, dict):
                endpoint_value = v.get("path", None)

            if not endpoint_value or not isinstance(endpoint_value, str):
                raise ValueError(
                    f"Invalid endpoint value for '{k}'. Given value: {endpoint_value}"
                )

            url_map.append(
                (
                    f"^{self.name}/{endpoint_value.lstrip('/')}$",
                    getattr(self, f"{k}_endpoint"),
                )
            )
            _endpoint = f"{self._backend_url}/{endpoint_value.lstrip('/')}"
            self._log_debug(
                "OpenID4VPBackend", f"Exposing backend entity endpoint = {_endpoint}"
            )
            match k:
                case "get_response":
                    self.registered_get_response_endpoint = _endpoint
                case "response":
                    self.absolute_response_url = _endpoint
                case "request":
                    self.absolute_request_url = _endpoint
                case "status":
                    self.absolute_status_url = _endpoint
                case _:
                    pass
        return url_map

    def start_auth(self, context: Context, internal_request) -> Response:
        """
        This is the start up function of the backend authorization.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Response

        :param context: the request context
        :param internal_request: Information about the authorization request
        :return: response
        """
        return self.pre_request_endpoint(context, internal_request)

    def pre_request_endpoint(
        self, context: Context, internal_request, **kwargs
    ) -> Response:
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
            "pre_request_endpoint", context, "internal_request", internal_request
        )

        session_id = context.state["SESSION_ID"]
        state = str(uuid.uuid4())

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

        # PAR
        payload = {
            "client_id": self.client_id,
            "request_uri": f"{self.absolute_request_url}?id={state}",
        }

        response_url = build_authorization_request_url(
            self.config["authorization"]["url_scheme"], payload
        )

        if flow_typ == RemoteFlowType.SAME_DEVICE:
            return self._same_device_http_response(response_url)
        elif flow_typ == RemoteFlowType.CROSS_DEVICE:
            return self._cross_device_http_response(response_url, state)

    def _same_device_http_response(self, response_url: str) -> Response:
        return Redirect(response_url)

    def _cross_device_http_response(self, response_url: str, state: str) -> Response:
        result = self.template.qrcode_page.render(
            {
                "qrcode_color": self.config["qrcode"]["color"],
                "qrcode_text": response_url,
                "qrcode_size": self.config["qrcode"]["size"],
                "qrcode_logo_path": self.config["qrcode"]["logo_path"],
                "qrcode_expiration_time": self.config["qrcode"]["expiration_time"],
                "state": state,
                "status_endpoint": self.absolute_status_url,
            }
        )
        return Response(result, content="text/html; charset=utf8", status="200")

    def get_response_endpoint(self, context: Context) -> Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance after the authorization is done for retrieving the response.

        :type context: the context of current request
        :param context: the request context

        :return: a response containing the response
        :rtype: satosa.response.Response
        """

        self._log_function_debug("get_response_endpoint", context)
        resp_code = context.qs_params.get("response_code", None)
        session_id = context.state.get("SESSION_ID", None)

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
        return self.auth_callback_func(context, resp)

    def status_endpoint(self, context: Context) -> JsonResponse:
        """
        This endpoint is called by the User-Agent/Wallet Instance to check the status of the request.

        :type context: the context of current request
        :param context: the request context

        :return: a response containing the status of the request
        :rtype: satosa.response.Response
        """

        self._log_function_debug("status_endpoint", context)

        session_id = context.state["SESSION_ID"]

        try:
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

        request_object = session.get("request_object", None)
        if request_object:
            if iat_now() > request_object["exp"]:
                return self._status_session_expired_response(context)

        if session["finalized"]:
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

    @property
    def db_engine(self) -> DBEngine:
        """
        Returns the DBEngine instance used by the class
        """
        if not self._db_engine:
            self._db_engine = DBEngine(self.config["storage"])

        try:
            self._db_engine.is_connected
        except Exception as e:
            if getattr(self, "_db_engine", None):
                self._log_debug(
                    "OpenID4VP db storage handling",
                    f"connection check silently fails and get restored: {e}",
                )
            self._db_engine = DBEngine(self.config["storage"])

        return self._db_engine

    @property
    def default_metadata_private_jwk(self) -> tuple:
        """
        Returns the default metadata private JWK
        """
        return tuple(self.metadata_jwks_by_kids.values())[0]

    @property
    def server_url(self):
        """
        Returns the server url
        """
        return self._server_url

    def load_credential_presentation_handlers(self):
        try:
            from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
            return load_credential_presentation_handlers(
                self.config, self.trust_evaluator, self.config.get("jwt", {}).get("sig_alg_supported", []))
        except ImportError as e:
            raise ImportError(f"Failed to import credential_presentation handlers: {e}")