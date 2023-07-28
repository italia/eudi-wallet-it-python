import base64
import json
import logging
import uuid

from datetime import datetime, timedelta
from typing import Union
from urllib.parse import urlencode, quote_plus

from satosa.context import Context
import satosa.logging_util as lu
from satosa.backends.base import BackendModule
from pyeudiw.satosa.exceptions import (
    BadRequestError,
    NoBoundEndpointError
)
from satosa.internal import InternalData
from satosa.response import Redirect, Response

from pyeudiw.oauth2.dpop import DPoPVerifier
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper, JWEHelper
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.satosa.html_template import Jinja2TemplateHandler
from pyeudiw.satosa.response import JsonResponse
from pyeudiw.tools.qr_code import QRCode
from pyeudiw.tools.mobile import is_smartphone
from pyeudiw.tools.utils import iat_now
from pyeudiw.openid4vp.schema import ResponseSchema as ResponseValidator
from pyeudiw.sd_jwt import load_specification_from_yaml_string
from pyeudiw.openid4vp import check_vp_token


logger = logging.getLogger("openid4vp_backend")


class OpenID4VPBackend(BackendModule):
    """
    A backend module (acting as a OpenID4VP SP).
    """

    def __init__(self, auth_callback_func, internal_attributes, config, base_url, name):
        """
        OpenID4VP backend module.
        :param auth_callback_func: Callback should be called by the module after the authorization
        in the backend is done.
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :param config: Configuration parameters for the module.
        :param base_url: base url of the service
        :param name: name of the plugin
        :type auth_callback_func:
        (satosa.context.Context, satosa.internal.InternalData) -> satosa.response.Response
        :type internal_attributes: dict[string, dict[str, str | list[str]]]
        :type config: dict[str, dict[str, str] | list[str]]
        :type base_url: str
        :type name: str
        """
        super().__init__(auth_callback_func, internal_attributes, base_url, name)

        self.client_id = config['metadata']['client_id']

        self.absolute_redirect_url = config['metadata']['redirect_uris'][0]
        self.absolute_request_url = config['metadata']['request_uris'][0]

        self.qrcode_settings = config['qrcode_settings']
        self.config = config

        self.default_exp = int(self.config['jwt_settings']['default_exp'])

        # dumps public jwks in the metadata
        self.config['metadata']['jwks'] = config["metadata_jwks"]

        self.federation_jwk = JWK(
            self.config['federation']['federation_jwks'][0])
        self.metadata_jwk = JWK(self.config["metadata_jwks"][0])

        # HTML template loader
        self.template = Jinja2TemplateHandler(config)

        self.sd_jwt = self.config["sd_jwt"]
        self.sd_specification = load_specification_from_yaml_string(
            self.sd_jwt["sd_specification"])

        logger.debug(
            lu.LOG_FMT.format(
                id="OpenID4VP init",
                message=f"Loaded configuration:\n{json.dumps(config)}"
            )
        )

    def register_endpoints(self):
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
                    f"^{v.lstrip('/')}$", getattr(self, f"{k}_endpoint")
                )
            )

            logger.debug(
                lu.LOG_FMT.format(
                    id="OpenID4VP endpoint registration",
                    message=f"[OpenID4VP] Loaded endpoint: '{k}'"
                )
            )

        return url_map

    def start_auth(self, context, internal_request):
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

    def _log(self, context: Context, level: str, message: str):
        log_level = getattr(logger, level)
        log_level(
            lu.LOG_FMT.format(
                id=lu.get_session_id(context.state),
                message=message
            )
        )

    def entity_configuration_endpoint(self, context, *args):

        _now = datetime.now()
        data = {
            "exp": int((_now + timedelta(minutes=self.default_exp)).timestamp()),
            "iat": iat_now(),
            "iss": self.client_id,
            "sub": self.client_id,
            "jwks": {
                "keys": [self.federation_jwk.public_key]
            },
            "metadata": {
                self.config['federation']["metadata_type"]: self.config['metadata']
            },
            "authority_hints": self.config['federation']['federation_authorities']
        }
        jwshelper = JWSHelper(self.federation_jwk)

        return Response(
            jwshelper.sign(
                protected={
                    "alg": self.config['federation']["default_sig_alg"],
                    "kid": self.federation_jwk.public_key["kid"],
                    "typ": "entity-statement+jwt"
                },
                plain_dict=data
            ),
            status="200",
            content="application/entity-statement+jwt"
        )

    def pre_request_endpoint(self, context, internal_request, **kwargs):

        # PAR
        payload = {
            'client_id': self.client_id,
            'request_uri': self.absolute_request_url
        }

        url_params = urlencode(payload, quote_via=quote_plus)

        if is_smartphone(context.http_headers.get('HTTP_USER_AGENT')):
            # Same Device flow
            res_url = f'{self.config["authorization"]["url_scheme"]}://authorize?{url_params}'
            return Redirect(res_url)

        # Cross Device flow
        res_url = f'{self.client_id}?{url_params}'

        # response = base64.b64encode(res_url.encode())
        qrcode = QRCode(res_url, **self.config['qrcode_settings'])
        stream = qrcode.for_html()

        result = self.template.qrcode_page.render(
            {"title": "frame the qrcode", 'qrcode_base64': base64.b64encode(
                stream.encode()).decode()}
        )
        return Response(result, content="text/html; charset=utf8", status="200")

    def _translate_response(self, response, issuer):
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
        timestamp = response.get(
            "auth_time",
            response.get('iat', iat_now())
        )

        # it may depends by credential type and attested security context evaluated
        # if WIA was previously submitted by the Wallet

        # auth_class_ref = response.get("acr", response.get("amr", UNSPECIFIED))
        # auth_info = AuthenticationInformation(auth_class_ref, timestamp, issuer)
        # internal_resp = InternalData(auth_info=auth_info)
        internal_resp = InternalData()
        internal_resp.attributes = self.converter.to_internal(
            "openid4vp", response)
        # response["sub"]

        # TODO: create a subject id with a pairwised strategy, mixing user attrs hash + wallet instance hash. Instead of uuid4
        internal_resp.subject_id = str(uuid.uuid4())
        return internal_resp

    def _handle_vp(self, vp_token: str, context: Context) -> dict:
        valid, value = check_vp_token(
            vp_token, self.config, self.sd_specification, self.sd_jwt)
        if not valid:
            raise value
        elif not value.get("nonce", None):
            _msg = "vp_token's nonce not present"
            self._log(context, level='error', message=_msg)
            return JsonResponse(
                {
                    "error": "parameter_absent",
                    "error_description": _msg
                },
                status="400"
            )

        return value

    def redirect_endpoint(self, context, *args):
        self.metadata_jwk

        if context.request_method.lower() != 'post':
            raise BadRequestError("HTTP Method not supported")

        if context.request_uri not in self.config["metadata"]['redirect_uris']:
            raise NoBoundEndpointError("request_uri not valid")

        # take the encrypted jwt, decrypt with my public key (one of the metadata) -> if not -> exception
        jwt = context.request["response"]
        jwk = JWK(self.config["federation"]
                  ["federation_jwks"][0], key_type="RSA")

        jweHelper = JWEHelper(jwk)
        try:
            decrypted_data = jweHelper.decrypt(jwt)
        except Exception as e:
            _msg = f"Response decryption error: {e}"
            self._log(context, level='error', message=_msg)
            raise BadRequestError(_msg)

        # TODO: get state, do lookup on the db -> if not -> exception
        # TODO Fix this field handling
        state = decrypted_data.get("state", None)
        if not state:
            _msg = f"Response state missing"
            # state is OPTIONAL in openid4vp ...
            self._log(context, level='warning', message=_msg)

        # check with pydantic on the JWT schema
        try:
            ResponseValidator(**decrypted_data)
        except Exception as e:
            _msg = f"Response validation error: {e}"
            self._log(context, level='error', message=_msg)
            raise BadRequestError(_msg)

        # check if vp_token is string or array, if array iter all the elements
        # for each single vp token, take the credential within it, use cnf.jwk to validate the vp token signature -> if not exception
        vp_token = (
            [decrypted_data["vp_token"]]
            if isinstance(decrypted_data["vp_token"], str)
            else decrypted_data["vp_token"]
        )

        nonce = None
        claims = []
        for vp in vp_token:

            try:
                result = self._handle_vp(vp, context)
            except Exception as e:
                _msg = f"VP parsing error: {e}"
                self._log(context, level='error', message=_msg)
                return JsonResponse(
                    {
                        "error": "unsupported_response_type",
                        "error_description": _msg
                    },
                    status="400"
                )

            # TODO: this is not clear ... since the nonce must be taken from the originatin authz request, taken from the storage (mongodb)
            if not nonce:
                nonce = result["nonce"]
            elif nonce != result["nonce"]:
                _msg = "Presentation has divergent nonces"
                self._log(context, level='error', message=_msg)
                return JsonResponse(
                    {
                        "error": "invalid_token",
                        "error_description": _msg
                    },
                    status="401"
                )
            else:
                claims.append(result["claims"])

        # TODO: establish the trust with the issuer of the credential by checking it to the revocation
        # inspect VP's iss or trust_chain if available or x5c if available

        # TODO: check the revocation of the credential

        # for all the valid credentials, take the payload and the disclosure and discose the user attributes
        # returns the user attributes ...
        all_user_claims = dict()

        for claim in claims:
            all_user_claims.update(claim)

        self._log(context, level='debug',
                  message=f"Wallet disclosure: {all_user_claims}")

        # TODO: define "issuer"  ... it MUST be not an empty dictionary
        _info = {"issuer": {}}

        internal_resp = self._translate_response(
            all_user_claims, _info["issuer"]
        )
        return self.auth_callback_func(context, internal_resp)

    def _request_endpoint_dpop(self, context, *args) -> Union[JsonResponse, None]:
        """ This validates, if any, the DPoP http request header """

        if context.http_headers and 'HTTP_AUTHORIZATION' in context.http_headers:
            # the wallet instance MAY use the endpoint authentication to give its WIA

            # TODO - validate the trust to the Wallet Provider
            # using the TA public key validate trust_chain and or x5c

            # take WIA
            wia = unpad_jwt_payload(context.http_headers['HTTP_AUTHORIZATION'])

            # TODO: validate wia scheme using pydantic

            try:
                dpop = DPoPVerifier(
                    public_jwk=wia['cnf']['jwk'],
                    http_header_authz=context.http_headers['HTTP_AUTHORIZATION'],
                    http_header_dpop=context.http_headers['HTTP_DPOP']
                )
            except Exception as e:
                _msg = f"DPoP verification error: {e}"
                self._log(context, level='error', message=_msg)
                return JsonResponse(
                    {
                        "error": "invalid_param",
                        "error_description": _msg
                    },
                    status="400"
                )

            if not dpop.is_valid:
                _msg = "DPoP validation error"
                self._log(context, level='error', message=_msg)
                return JsonResponse(
                    {
                        "error": "invalid_param",
                        "error_description": _msg
                    },
                    status="400"
                )

            # TODO: assert and configure the wallet capabilities
            # TODO: assert and configure the wallet  Attested Security Context

        else:
            # TODO - check that this logging system works ...
            _msg = (
                "The Wallet Instance didn't provide its Wallet Instance Attestation "
                "a default set of capabilities and a low security level are accorded."
            )
            self._log(context, level='warning', message=_msg)

    def request_endpoint(self, context, *args):
        jwk = self.metadata_jwk

        # check DPOP for WIA if any
        dpop_validation_error = self._request_endpoint_dpop(context)
        if dpop_validation_error:
            return dpop_validation_error

        # TODO: do customization if the WIA is available

        # TODO: take the response and extract from jwt the public key of holder

        # verify the jwt
        helper = JWSHelper(jwk)
        data = {
            "scope": ' '.join(self.config['authorization']['scopes']),
            "client_id_scheme": "entity_id",  # that's federation.
            "client_id": self.client_id,
            "response_mode": "direct_post.jwt",  # only HTTP POST is allowed.
            "response_type": "vp_token",
            "response_uri": self.config["metadata"]["redirect_uris"][0],
            "nonce": str(uuid.uuid4()),
            "state": str(uuid.uuid4()),
            "iss": self.client_id,
            "iat": iat_now(),
            "exp": iat_now() + (self.default_exp * 60)  # in seconds
        }
        jwt = helper.sign(data)
        response = {"response": jwt}

        return JsonResponse(
            response,
            status="200"
        )

    def handle_error(
        self,
        context: dict,
        message: str,
        troubleshoot: str = "",
        err="",
        err_code="500",
        template_path="templates",
        error_template="error.html",
    ):

        # TODO: evaluate with UX designers if Jinja2 template
        # loader and rendering is required, it seems not.
        self._log(context, level='error',
                  message=f"{message}: {err}. {troubleshoot}")

        return JsonResponse(
            {
                "message": message,
                "troubleshoot": troubleshoot
            },
            status=err_code
        )
