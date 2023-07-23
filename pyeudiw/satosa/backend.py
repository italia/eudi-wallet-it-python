import base64
import json
import logging
import uuid

from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus

from satosa.backends.base import BackendModule
from satosa.response import Redirect, Response

from pyeudiw.satosa.html_template import Jinja2TemplateHandler
from pyeudiw.tools.qr_code import QRCode
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.tools.mobile import is_smartphone

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

        logger.debug(f"Loaded configuration:\n{json.dumps(config)}")

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
            logger.info(f"[OpenID4VP] Loaded endpoint: '{k}'")

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

        res_url = f'{self.config["authorization_url_scheme"]}://authorize?{url_params}'
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

    def redirect_endpoint(self, context, *args):
        jwk = self.metadata_jwk

        helper = JWSHelper(jwk)
        data = {} #TODO
        jwt = helper.sign(data)
        response = {"request": jwt}

        return Response(
            json.dumps(response),
            status="200",
            content="application/jose; charset=utf8"
        )

    def request_endpoint(self, context, *args):
        jwk = self.metadata_jwk

        # validate, if any, the DPoP http request header

        if context.http_headers and 'HTTP_AUTHORIZATION' in context.http_headers:
            # the wallet instance MAY use the endpoint authentication to give its WIA
            # dpop = DPoPVerifier()
            pass

        helper = JWSHelper(jwk)
        data = {
            "state": "3be39b69-6ac1-41aa-921b-3e6c07ddcb03",
            "vp_token": "eyJhbGciOiJFUzI1NiIs...PT0iXX0",
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "eu.europa.ec.eudiw.pid.it.1:unique_id",
                        "path": "$.vp_token.verified_claims.claims._sd[0]",
                        "format": "vc+sd-jwt"
                    },
                    {
                        "id": "eu.europa.ec.eudiw.pid.it.1:given_name",
                        "path": "$.vp_token.verified_claims.claims._sd[1]",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        }
        jwt = helper.sign(data)

        response = {"response": jwt}

        return Response(
            json.dumps(response),
            status="200",
            content="text/json; charset=utf8"
        )

    def handle_error(
        self,
        message: str,
        troubleshoot: str = "",
        err="",
        template_path="templates",
        error_template="spid_login_error.html",
    ):
        """
        Todo: Jinja2 template loader and rendering :)
        """
        logger.error(f"Failed to parse authn request: {message} {err}")
        result = json.dumps(
            {"message": message, "troubleshoot": troubleshoot}
        )
        return Response(result, content="text/json; charset=utf8", status="403")

    def authn_response(self, context, binding):
        """
        Endpoint for the idp response
        :type context: satosa.context.Context
        :type binding: str
        :rtype: satosa.response.Response
        :param context: The current context
        :param binding: The saml binding type
        :return: response
        """
