import uuid
from typing import Callable
from urllib.parse import quote_plus, urlencode

from pydantic import ValidationError
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect, Response

from pyeudiw.satosa.schemas.config import PyeudiwBackendConfig
from pyeudiw.jwk import JWK
from pyeudiw.satosa.utils.html_template import Jinja2TemplateHandler
from pyeudiw.satosa.utils.respcode import ResponseCodeSource
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.satosa.utils.trust import BackendTrust
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.tools.mobile import is_smartphone
from pyeudiw.tools.utils import iat_now
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

from ..interfaces.openid4vp_backend import OpenID4VPBackendInterface


class OpenID4VPBackend(OpenID4VPBackendInterface, BackendTrust):
    def __init__(
        self,
        auth_callback_func: Callable[[Context, InternalData], Response],
        internal_attributes: dict[str, dict[str, str | list[str]]],
        config: dict[str, dict[str, str] | list[str]],
        base_url: str,
        name: str
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

        self.config = config

        self.client_id = f"{base_url}/{name}"
        self.config['metadata']['client_id'] = self.client_id

        self.config['metadata']['response_uris_supported'] = []
        self.config['metadata']['response_uris_supported'].append(
            f"{self.client_id}/response-uri")

        self.config['metadata']['request_uris'] = []
        self.config['metadata']['request_uris'].append(
            f"{self.client_id}/request-uri")

        self.default_exp = int(self.config['jwt']['default_exp'])

        self.metadata_jwks_by_kids = {
            i['kid']: i for i in self.config['metadata_jwks']
        }

        self.config['metadata']['jwks'] = {"keys": [
            JWK(i).public_key for i in self.config['metadata_jwks']
        ]}

        # HTML template loader
        self.template = Jinja2TemplateHandler(self.config["ui"])

        # it will be filled by .register_endpoints
        self.absolute_response_url = None
        self.absolute_request_url = None
        self.absolute_status_url = None
        self.registered_get_response_endpoint = None

        self._server_url = (
            self.base_url[:-1]
            if self.base_url[-1] == '/'
            else self.base_url
        )

        try:
            PyeudiwBackendConfig(**config)
        except ValidationError as e:
            debug_message = f"""The backend configuration presents the following validation issues: {e}"""
            self._log_warning("OpenID4VPBackend", debug_message)

        self.response_code_helper = ResponseCodeSource(self.config["response_code"]["sym_key"])
        trust_configuration = self.config.get("trust", {})
        self.trust_evaluator = CombinedTrustEvaluator.from_config(trust_configuration, self.db_engine)
        self.init_trust_resources()  # Questo carica risorse, metadata endpoint (sotto formate di attributi con pattern *_endpoint) etc, che satosa deve pubblicare

    def register_endpoints(self) -> list[tuple[str, Callable[[Context], Response]]]:
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        url_map = []
        for k, v in self.config['endpoints'].items():
            endpoint_value = v

            if isinstance(endpoint_value, dict):
                endpoint_value = v.get("path", None)

            if not endpoint_value or not isinstance(endpoint_value, str):
                raise ValueError(
                    f"Invalid endpoint value for \"{k}\". Given value: {endpoint_value}"
                )

            url_map.append(
                (
                    f"^{self.name}/{endpoint_value.lstrip('/')}$",
                    getattr(self, f"{k}_endpoint")
                )
            )
            _endpoint = f"{self.client_id}/{endpoint_value.lstrip('/')}"
            self._log_debug(
                "OpenID4VPBackend",
                f"Exposing backend entity endpoint = {_endpoint}"
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

    def pre_request_endpoint(self, context: Context, internal_request, **kwargs) -> Response:
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
            "pre_request_endpoint", context, "internal_request", internal_request)

        session_id = context.state["SESSION_ID"]
        state = str(uuid.uuid4())

        if not context.target_frontend:
            _msg = "Preventing session creation: context is not linked to any previous authn session."
            self._log_warning(context, _msg)
            return self._handle_400(
                context,
                "previous authn session not found. It seems that the flow did not started with a valid authn request to one of the configured frontend."
            )

        # Init session
        try:
            self.db_engine.init_session(
                state=state,
                session_id=session_id
            )
        except (StorageWriteError) as e:
            _msg = f"Error while initializing session with state {state} and {session_id}."
            self._log_error(context, f"{_msg} for the following reason {e}")
            return self._handle_500(context, _msg, e)

        except (Exception) as e:
            _msg = f"Error while initializing session with state {state} and {session_id}."
            self._log_error(context, _msg)
            return self._handle_500(context, _msg, e)

        # PAR
        payload = {
            'client_id': self.client_id,
            'request_uri': f"{self.absolute_request_url}?id={state}",
        }

        response_url = self._build_authz_request_url(payload)

        if is_smartphone(context.http_headers.get('HTTP_USER_AGENT')):
            # Same Device flow
            return Redirect(response_url)

        # Cross Device flow
        result = self.template.qrcode_page.render(
            {
                "qrcode_color": self.config["qrcode"]["color"],
                "qrcode_text": response_url,
                "qrcode_size": self.config["qrcode"]["size"],
                "qrcode_logo_path": self.config["qrcode"]["logo_path"],
                "qrcode_expiration_time": self.config["qrcode"]["expiration_time"],
                "state": state,
                "status_endpoint": self.absolute_status_url
            }
        )
        return Response(result, content="text/html; charset=utf8", status="200")

    def get_response_endpoint(self, context: Context) -> Response:

        self._log_function_debug("get_response_endpoint", context)
        resp_code = context.qs_params.get("response_code", None)
        session_id = context.state.get("SESSION_ID", None)

        if not session_id:
            return self._handle_400(context, "session id not found")

        state = ""
        try:
            state = self.response_code_helper.recover_state(resp_code)
        except Exception:
            return self._handle_400(context, "missing or invalid parameter [response_code]")

        finalized_session = None

        try:
            finalized_session = self.db_engine.get_by_state_and_session_id(
                state=state,
                session_id=session_id
            )
        except Exception as e:
            _msg = f"Error while retrieving internal response with response_code {resp_code} and session_id {session_id}: {e}"
            return self._handle_401(context, _msg, e)

        if not finalized_session:
            return self._handle_400(context, "session not found or invalid")

        _now = iat_now()
        _exp = finalized_session['request_object']['exp']
        if _exp < _now:
            return self._handle_400(context, f"session expired, request object exp is {_exp} while now is {_now}")

        internal_response = InternalData()
        resp = internal_response.from_dict(
            finalized_session['internal_response']
        )

        return self.auth_callback_func(
            context,
            resp
        )

    def status_endpoint(self, context: Context) -> JsonResponse:

        self._log_function_debug("status_endpoint", context)

        session_id = context.state["SESSION_ID"]
        _err_msg = ""
        state = None

        try:
            state = context.qs_params["id"]
        except TypeError as e:
            _err_msg = f"No query params found: {e}"
        except KeyError as e:
            _err_msg = f"No id found in qs_params: {e}"

        if _err_msg:
            return self._handle_400(context, _err_msg)

        try:
            session = self.db_engine.get_by_state_and_session_id(
                state=state, session_id=session_id
            )
        except Exception as e:
            _msg = f"Error while retrieving session by state {state} and session_id {session_id}: {e}"
            return self._handle_401(context, _msg)

        request_object = session.get("request_object", None)
        if request_object:
            if iat_now() > request_object["exp"]:
                return self._handle_403("expired", "Request object expired")

        if (session["finalized"] is True):
            resp_code = self.response_code_helper.create_code(state)
            return JsonResponse(
                {
                    "redirect_uri": f"{self.registered_get_response_endpoint}?response_code={resp_code}"
                },
                status="200"
            )
        else:
            if request_object is not None:
                return JsonResponse(
                    {
                        "response": "Accepted"
                    },
                    status="202"
                )

            return JsonResponse(
                {
                    "response": "Request object issued"
                },
                status="201"
            )

    @property
    def db_engine(self) -> DBEngine:
        """Returns the DBEngine instance used by the class"""
        try:
            self._db_engine.is_connected
        except Exception as e:
            if getattr(self, '_db_engine', None):
                self._log_debug(
                    "OpenID4VP db storage handling",
                    f"connection check silently fails and get restored: {e}"
                )
            self._db_engine = DBEngine(self.config["storage"])

        return self._db_engine

    def _build_authz_request_url(self, payload: dict) -> str:
        scheme = self.config["authorization"]["url_scheme"]
        if "://" not in scheme:
            scheme = scheme + "://"
        if not scheme.endswith("/"):
            scheme = scheme + "/"
        # NOTE: path component is currently unused by the protocol, but currently
        # we leave it there as 'authorize' to stress the fact that this is an
        # OAuth 2.0 request modified by JAR (RFC9101)
        path = "authorize"
        query_params = urlencode(payload, quote_via=quote_plus)
        return f"{scheme}{path}?{query_params}"

    @property
    def default_metadata_private_jwk(self) -> tuple:
        """Returns the default metadata private JWK"""
        return tuple(self.metadata_jwks_by_kids.values())[0]

    @property
    def server_url(self):
        """Returns the server url"""
        return self._server_url
