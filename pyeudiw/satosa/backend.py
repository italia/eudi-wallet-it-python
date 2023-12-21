import base64
import datetime
import json
import hashlib
import logging
import uuid

from urllib.parse import quote_plus, urlencode

import satosa.logging_util as lu
from satosa.backends.base import BackendModule
from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect, Response

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.satosa.exceptions import (
    NotTrustedFederationError
)
from pyeudiw.satosa.dpop import BackendDPoP
from pyeudiw.satosa.html_template import Jinja2TemplateHandler
from pyeudiw.satosa.response import JsonResponse
from pyeudiw.satosa.trust import BackendTrust
from pyeudiw.tools.mobile import is_smartphone
from pyeudiw.tools.qr_code import QRCode
from pyeudiw.tools.utils import iat_now, exp_from_now
from pyeudiw.openid4vp.schemas.response import ResponseSchema
from pyeudiw.openid4vp.direct_post_response import DirectPostResponse
from pyeudiw.openid4vp.exceptions import (
    KIDNotFound,
    InvalidVPToken, VPNotFound, NoNonceInVPToken, VPInvalidNonce
)
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.federation.schemas.wallet_relying_party import WalletRelyingParty
from pyeudiw.openid4vp.vp import Vp

from typing import Callable
from pydantic import ValidationError

from .exceptions import HTTPError
from .base_http_error_handler import BaseHTTPErrorHandler
from pyeudiw.tools.base_logger import BaseLogger

class OpenID4VPBackend(BackendModule, BackendTrust, BackendDPoP, BaseHTTPErrorHandler, BaseLogger):
    """
    A backend module (acting as a OpenID4VP SP).
    """

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
        self.client_id = self.config['metadata']['client_id']
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
        self.absolute_redirect_url = None
        self.absolute_request_url = None
        self.absolute_status_url = None
        self.registered_get_response_endpoint = None

        # resolve metadata pointers/placeholders
        self._render_metadata_conf_elements()
        self.init_trust_resources()
        try:
            WalletRelyingParty(**config['metadata'])
        except ValidationError as e:
            debug_message = f"""The backend configuration presents the following validation issues: {e}"""
            self._log_warning("OpenID4VPBackend", debug_message)
        self._log_debug("OpenID4VP init", f"Loaded configuration: {json.dumps(config)}")

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
            url_map.append(
                (
                    f"^{self.name}/{v.lstrip('/')}$",
                    getattr(self, f"{k}_endpoint")
                )
            )
            _endpoint = f"{self.client_id}{v}"
            self._log_debug(
                "OpenID4VPBackend",
                f"Exposing backend entity endpoint = {_endpoint}"
            )
            if k == 'get_response':
                self.registered_get_response_endpoint = _endpoint
            elif k == 'redirect':
                self.absolute_redirect_url = _endpoint
            elif k == 'request':
                self.absolute_request_url = _endpoint
            elif k == "status":
                self.absolute_status_url = _endpoint
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

        self._log_function_debug("pre_request_endpoint", context, "internal_request", internal_request)

        session_id = context.state["SESSION_ID"]
        state = str(uuid.uuid4())

        # TODO: do not init the session if the context is not linked to any
        #       previous authn session (avoid to init sessions for users that has not requested an auth to a frontend)

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
        url_params = urlencode(payload, quote_via=quote_plus)

        if is_smartphone(context.http_headers.get('HTTP_USER_AGENT')):
            # Same Device flow
            res_url = f'{self.config["authorization"]["url_scheme"]}://authorize?{url_params}'
            return Redirect(res_url)

        # Cross Device flow
        res_url = f'{self.client_id}?{url_params}'

        result = self.template.qrcode_page.render(
            {
                "qrcode_color" : self.config["qrcode"]["color"],
                "qrcode_text": res_url,
                "state": state,
                "status_endpoint": self.absolute_status_url
            }
        )
        return Response(result, content="text/html; charset=utf8", status="200")

    def redirect_endpoint(self, context: Context, *args: tuple) -> Redirect | JsonResponse:
        """
        This endpoint is called by the User-Agent/Wallet Instance after the user has been authenticated.

        :type context: the context of current request
        :param context: the request context

        :return: a redirect to the User-Agent/Wallet Instance, if is in same device flow, or a json response if is in cross device flow.
        :rtype: Redirect | JsonResponse
        """

        self._log_function_debug("redirect_endpoint", context, "args", args)

        if context.request_method.lower() != 'post':
            # raise BadRequestError("HTTP Method not supported")
            return self._handle_400(context, "HTTP Method not supported")

        _endpoint = f'{self.server_url}{context.request_uri}'
        if self.config["metadata"].get('redirect_uris', None):
            if _endpoint not in self.config["metadata"]['redirect_uris']:
                return self._handle_400(context, "request_uri not valid")

        # take the encrypted jwt, decrypt with my public key (one of the metadata) -> if not -> exception
        jwt = context.request.get("response", None)
        if not jwt:
            _msg = f"Response error, missing JWT"
            self._log_error(context, _msg)
            return self._handle_400(context, _msg)

        try:
            vpt = DirectPostResponse(jwt, self.metadata_jwks_by_kids)
            
            debug_message = f"Redirect uri endpoint Response using direct post contains: {vpt.payload}"
            self._log_debug(context, debug_message)

            ResponseSchema(**vpt.payload)
        except Exception as e:
            _msg = f"DirectPostResponse parse and validation error: {e}"
            self._log_error(context, _msg)
            return self._handle_400(context, _msg, HTTPError(f"Error:{e}, with JWT: {jwt}"))

        # state MUST be present in the response since it was in the request
        # then do lookup on the db -> if not -> exception
        state = vpt.payload.get("state", None)
        if not state:
            return self._handle_400(context, _msg, HTTPError(f"{_msg} with: {vpt.payload}"))

        try:
            stored_session = self.db_engine.get_by_state(state=state)
        except Exception as e:
            _msg = f"Session lookup by state value failed"
            return self._handle_400(context, _msg, e)

        if stored_session["finalized"]:
            _msg = f"Session already finalized"
            return self._handle_400(context, _msg, HTTPError(_msg))

        try:
            vpt.load_nonce(stored_session['nonce'])
            vps: list[Vp] = vpt.get_presentation_vps()
            vpt.validate()
            
        except VPNotFound as e:
            _msg = "Error while retrieving VP. Payload 'vp_token' is empty or has an unexpected value."
            return self._handle_400(context, _msg, e)

        except NoNonceInVPToken as e:
            _msg = "Error while validating VP: vp has no nonce."
            return self._handle_400(context, _msg, e)

        except VPInvalidNonce as e:
            _msg = "Error while validating VP: unexpected value."
            return self._handle_400(context, _msg, e)
        
        except Exception as e:
            _msg = (
                "DirectPostResponse content parse and validation error. "
                "Single VPs are faulty."
            )
            return self._handle_400(context, _msg, e)

        # evaluate the trust to each credential issuer found in the vps
        # look for trust chain or x509 or do discovery!
        cred_issuers = tuple(vpt.credentials_by_issuer.keys())
        attributes_by_issuers = {k: {} for k in cred_issuers}

        for vp in vps:
            try:
                # establish the trust with the issuer of the credential by checking it to the revocation
                # inspect VP's iss or trust_chain if available or x5c if available
                # TODO: X.509 as alternative to Federation

                # for each single vp token, take the credential within it, use cnf.jwk to validate the vp token signature -> if not exception
                # establish the trust to each credential issuer
                tchelper = self._validate_trust(context, vp.payload['vp'])

                if not tchelper.is_trusted:
                    return self._handle_400(context, f"Trust Evaluation failed for {tchelper.entity_id}")

                # TODO: generalyze also for x509
                credential_jwks = tchelper.get_trusted_jwks(
                    metadata_type='openid_credential_issuer'
                )
                vp.set_credential_jwks(credential_jwks) 
            except InvalidVPToken:
                return self._handle_400(context, f"Cannot validate VP: {vp.jwt}")
            except ValidationError as e:
                return self._handle_400(context, f"Error validating schemas: {e}")
            except KIDNotFound as e:
                return self._handle_400(context, f"Kid error: {e}")
            except NotTrustedFederationError as e:
                return self._handle_400(context, f"Not trusted federation error: {e}")
            except Exception as e:
                return self._handle_400(context, f"VP parsing error: {e}")

            # the trust is established to the credential issuer, then we can get the disclosed user attributes
            # TODO - what if the credential is different from sd-jwt? -> generalyze within Vp class

            try:
                vp.verify_sdjwt(
                    issuer_jwks_by_kid = {
                        i['kid']: i for i in vp.credential_jwks}
                )
            except Exception as e:
                return self._handle_400(context, f"VP SD-JWT validation error: {e}")

            # vp.result
            attributes_by_issuers[vp.credential_issuer] = vp.disclosed_user_attributes

            debug_message = f"Disclosed user attributes from {vp.credential_issuer}: {vp.disclosed_user_attributes}"
            self._log_debug(context, debug_message)

            # TODO: check the revocation of the credential
            # ...

        # for all the valid credentials, take the payload and the disclosure and disclose user attributes
        # returns the user attributes ...
        all_user_attributes = dict()
        for i in attributes_by_issuers.values():
            all_user_attributes.update(**i)

        self._log_debug(context, f"Wallet disclosure: {all_user_attributes}")

        # TODO: not sure that we want these issuers in the following form ... please recheck.
        _info = {"issuer": ';'.join(cred_issuers)}
        internal_resp = self._translate_response(
            all_user_attributes, _info["issuer"], context
        )

        try:
            self.db_engine.update_response_object(
                stored_session['nonce'], state, internal_resp
            )
            # authentication finalized!
            self.db_engine.set_finalized(stored_session['document_id'])
            if self.effective_log_level == logging.DEBUG:
                stored_session = self.db_engine.get_by_state(state=state)
                self._log_debug(context, f"Session update on storage: {stored_session}")

        except StorageWriteError as e:
            # TODO - do we have to block in the case the update cannot be done?
            self._log_error(context, f"Session update on storage failed: {e}")
            return self._handle_500(context, f"Cannot update response object.", e)

        if stored_session['session_id'] == context.state["SESSION_ID"]:
            # Same device flow
            return Redirect(
                self.registered_get_response_endpoint
            )
        else:
            # Cross device flow
            return JsonResponse(
                {
                    "status": "OK"
                },
                status="200"
            )

    def request_endpoint(self, context: Context, *args) -> JsonResponse:
        """
        This endpoint is called by the User-Agent/Wallet Instance to retrieve the signed signed Request Object.

        :type context: the context of current request
        :param context: the request context
        :param args: the request arguments
        :type args: tuple

        :return: a json response containing the request object
        :rtype: JsonResponse
        """

        self._log_function_debug("request_endpoint", context, "args", args)

        # check DPOP for WIA if any
        try:
            dpop_validation_error: JsonResponse = self._request_endpoint_dpop(
                context
            )
            if dpop_validation_error:
                return dpop_validation_error
        except Exception as e:
            _msg = f"[DPoP VALIDATION ERROR] WIA evalution error: {e}."
            return self._handle_401(context, _msg, e)

        try:
            state = context.qs_params["id"]
        except Exception as e:
            _msg = (
                "Error while retrieving id from qs_params: "
                f"{e.__class__.__name__}: {e}"
            )
            return self._handle_400(context, _msg, HTTPError(f"{e} with {context.__dict__}"))

        data = {
            "scope": ' '.join(self.config['authorization']['scopes']),
            "client_id_scheme": "entity_id",  # that's federation.
            "client_id": self.client_id,
            "response_mode": "direct_post.jwt",  # only HTTP POST is allowed.
            "response_type": "vp_token",
            "response_uri": self.absolute_redirect_url,
            "nonce": str(uuid.uuid4()),
            "state": state,
            "iss": self.client_id,
            "iat": iat_now(),
            # TODO: set an exp for the request in the general conf
            "exp": exp_from_now(minutes=5)
        }

        try:
            dpop_proof = context.http_headers['HTTP_DPOP']
            attestation = context.http_headers['HTTP_AUTHORIZATION']
        except KeyError as e:
            _msg = f"Error while accessing http headers: {e}"
            return self._handle_400(context, _msg, HTTPError(f"{e} with {context.__dict__}"))

        # take the session created in the pre-request authz endpoint
        try:
            document = self.db_engine.get_by_state(state)
            document_id = document["document_id"]
            self.db_engine.add_dpop_proof_and_attestation(
                document_id, dpop_proof, attestation
            )
            self.db_engine.update_request_object(document_id, data)

        except ValueError as e:
            _msg = "Error while retrieving request object from database."
            return self._handle_500(context, _msg, HTTPError(f"{e} with {context.__dict__}"))
        
        except (Exception, BaseException) as e:
            _msg = f"Error while updating request object: {e}"
            return self._handle_500(context, _msg, e)

        helper = JWSHelper(self.default_metadata_private_jwk)

        jwt = helper.sign(
            data,
            protected={'trust_chain': self.get_backend_trust_chain()}
        )
        response = {"response": jwt}
        return JsonResponse(
            response,
            status="200"
        )

    def get_response_endpoint(self, context: Context) -> Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance to retrieve the response of the authentication.
        
        :param context: the request context
        :type context: satosa.context.Context

        :return: a response containing the response object with the authenctication status
        :rtype: Response
        """

        self._log_function_debug("get_response_endpoint", context)

        state = context.qs_params.get("id", None)
        session_id = context.state["SESSION_ID"]
        finalized_session = None

        try:
            if state:
                # cross device
                finalized_session = self.db_engine.get_by_state_and_session_id(
                    state=state, session_id=session_id
                )
            else:
                # same device
                finalized_session = self.db_engine.get_by_session_id(
                    session_id=session_id
                )
        except Exception as e:
            _msg = f"Error while retrieving session by state {state} and session_id {session_id}: {e}"
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
        """
        This endpoint is called by the User-Agent/Wallet Instance the url to the response endpoint to finalize the process.

        :param context: the request context
        :type context: satosa.context.Context

        :return: a json response containing the status and the url to get the response
        :rtype: JsonResponse
        """

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
                return self._handle_403("expired", f"Request object expired")

        if session["finalized"]:
            #  return Redirect(
            #      self.registered_get_response_endpoint
            #  )
            return JsonResponse(
                {
                    "response_url": f"{self.registered_get_response_endpoint}?id={state}"
                },
                status="200"
            )
        else:
            return JsonResponse(
                {
                    "response": "Request object issued"
                },
                status="201"
            )

    def _render_metadata_conf_elements(self) -> None:
        """Renders the elements of config's metadata"""
        for k, v in self.config['metadata'].items():
            if isinstance(v, (int, float, dict, list)):
                continue
            if not v or len(v) == 0:
                continue
            if all((
                v[0] == '<',
                v[-1] == '>',
                '.' in v
            )):
                conf_section, conf_k = v[1:-1].split('.')
                self.config['metadata'][k] = self.config[conf_section][conf_k]

    def _translate_response(self, response: dict, issuer: str, context: Context):
        """
        Translates wallet response to SATOSA internal response.
        :type response: dict[str, str]
        :type issuer: str
        :type subject_type: str
        :rtype: InternalData
        :param response: Dictioary with attribute name as key.
        :param issuer: The oidc op that gave the repsonse.
        :param subject_type: public or pairwise according to oidc standard.
        :return: A SATOSA internal response.
        """
        # it may depends by credential type and attested security context evaluated
        # if WIA was previously submitted by the Wallet

        timestamp_epoch = (
            response.get("auth_time")
            or response.get("iat")
            or iat_now()
        )
        timestamp_dt = datetime.datetime.fromtimestamp(
            timestamp_epoch,
            datetime.timezone.utc
        )
        timestamp_iso = timestamp_dt.isoformat().replace("+00:00", "Z")

        auth_class_ref = (
            response.get("acr") or
            response.get("amr") or
            self.config["authorization"]["default_acr_value"]
        )
        auth_info = AuthenticationInformation(
            auth_class_ref, timestamp_iso, issuer)

        # TODO - ACR values
        internal_resp = InternalData(auth_info=auth_info)

        sub = ""
        pepper = self.config.get("user_attributes", {})['subject_id_random_value']
        for i in self.config.get("user_attributes", {}).get("unique_identifiers", []):
            if response.get(i):
                _sub = response[i]
                sub = hashlib.sha256(
                    f"{_sub}~{pepper}".encode(
                    )
                ).hexdigest()
                break

        if not sub:
            self._log(
                context,
                level='warning',
                message=(
                    "[USER ATTRIBUTES] Missing subject id from OpenID4VP presentation "
                    "setting a random one for interop for internal frontends"
                )
            )
            sub = hashlib.sha256(
                f"{json.dumps(response).encode()}~{pepper}".encode()
            ).hexdigest()

        response["sub"] = [sub]
        internal_resp.attributes = self.converter.to_internal(
            "openid4vp", response
        )
        internal_resp.subject_id = sub
        return internal_resp

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
    
    @property
    def default_metadata_private_jwk(self) -> tuple:
        """Returns the default metadata private JWK"""
        return tuple(self.metadata_jwks_by_kids.values())[0]
    
    @property
    def server_url(self):
        """Returns the server url"""
        return (
            self.base_url[:-1]
            if self.base_url[-1] == '/'
            else self.base_url
        )