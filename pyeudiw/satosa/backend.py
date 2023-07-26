import base64
import json
import logging
import uuid

from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus

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
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.satosa.html_template import Jinja2TemplateHandler
from pyeudiw.tools.qr_code import QRCode
from pyeudiw.tools.mobile import is_smartphone
from pyeudiw.tools.utils import iat_now
from pyeudiw.sd_jwt import verify_sd_jwt

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

    def entity_configuration_endpoint(self, context, *args):

        _now = datetime.now()
        data = {
            "exp": int((_now + timedelta(minutes=self.default_exp)).timestamp()),
            "iat": int(_now.timestamp()),
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
        payload = {
            'client_id': self.client_id,
            'request_uri': self.absolute_request_url
        }

        url_params = urlencode(payload, quote_via=quote_plus)

        res_url = f'{self.client_id}?{url_params}'
        # or
        # res_url = f'{self.config["authorization"]["url_scheme"]}://authorize?{url_params}' ?
        if is_smartphone(context.http_headers.get('HTTP_USER_AGENT')):
            return Redirect(res_url)

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
            response.get('iat', int(datetime.utcnow().timestamp()))
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
        internal_resp.subject_id = "take the subject id from the digital credential"
        return internal_resp

    def redirect_endpoint(self, context, *args):
        self.metadata_jwk

        if context.request_method.lower() != 'post':
            raise BadRequestError("HTTP Method not supported")

        if context.request_uri not in self.config["metadata"]['redirect_uris']:
            raise NoBoundEndpointError("request_uri not valid")

        # take the encrypted jwt, decrypt with my public key (one of the metadata) -> if not -> exception

        # get state and nonce, do lookup on the db -> if not -> exception

        # check with pydantic on the JWT schema

        # check if vp_token is string or array, if array iter all the elements

        # take the single vp token, take the credential within it, use cnf.jwk to validate the vp token signature -> if not exception

        # establish the trust with the issuer of the credential by checking it to the revocation

        # check the revocation of the credential

        # for all the valid credentials, take the payload and the disclosure and discose the user attributes

        # returns the user attributes .. something like the ...

        all_user_claims = dict()

        logger.debug(
            lu.LOG_FMT.format(
                id=lu.get_session_id(context.state),
                message=f"Wallet disclosure: {all_user_claims}"
            )
        )

        _info = {"issuer": {}}
        internal_resp = self._translate_response(
            all_user_claims, _info["issuer"]
        )
        return self.auth_callback_func(context, internal_resp)

    def _request_endpoint_dpop(self, context, *args):
        """ This validates, if any, the DPoP http request header """

        if context.http_headers and 'HTTP_AUTHORIZATION' in context.http_headers:
            # the wallet instance MAY use the endpoint authentication to give its WIA

            # TODO - validate the trust to the Wallet Provider
            # using the TA public key validate trust_chain and or x5c

            # take WIA
            wia = unpad_jwt_payload(context.http_headers['HTTP_AUTHORIZATION'])
            dpop = DPoPVerifier(
                public_jwk=wia['cnf']['jwk'],
                http_header_authz=context.http_headers['HTTP_AUTHORIZATION'],
                http_header_dpop=context.http_headers['HTTP_DPOP']
            )

            if not dpop.is_valid:
                #
                logger.error("MESSAGE HERE")
                raise Exception(
                    "return an HTTP response application/json with "
                    "the error and error_description "
                    "according to the UX design"
                )

            # TODO
            # assert and configure the wallet capabilities?
            # assert and configure the wallet  Attested Security Context?

        else:
            # TODO - check that this logging system works ...
            logger.warning(
                "The Wallet Instance didn't provide its Wallet Instance Attestation "
                "a default set of capabilities and a low security level are accorded."

            )

    def request_endpoint(self, context, *args):
        jwk = self.metadata_jwk

        # check DPOP for WIA if any
        self._request_endpoint_dpop(context)

        # TODO
        # take decision, do customization if the WIA is available
        
        # TODO
        # take the response and extract from jwt the public key of holder
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

        return Response(
            json.dumps(response),
            status="200",
            content="application/json; charset=utf8"
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
        logger.error(
            lu.LOG_FMT.format(
                id=lu.get_session_id(context.state),
                message=f"{message}: {err}. {troubleshoot}"
            )
        )

        result = json.dumps(
            {
                "message": message,
                "troubleshoot": troubleshoot
            }
        )
        return Response(
            result,
            content="text/json; charset=utf8",
            status=err_code
        )
