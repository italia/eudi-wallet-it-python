import uuid
from datetime import datetime, timedelta
import json
import logging
import base64

from urllib.parse import urlencode, quote_plus
from satosa.response import Response
from satosa.backends.base import BackendModule

from pyeudiw.tools.jwk import JWK
from pyeudiw.tools.jwt import JWSHelper

logger = logging.getLogger(__name__)


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
  
        self.client_id = config['wallet_relying_party']['client_id']
  
        self.default_sign_alg = config['default_sign_alg']
        
        self.absolute_redirect_url = config['wallet_relying_party']['redirect_uris'][0]
        self.absolute_request_url = config['wallet_relying_party']['request_uris'][0]

        self.qr_settings = config['qr_code_settings']
        self.token_exp_delta = config['jwks']['token_exp_delta']
    
        self.config = config
        
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
        raise NotImplementedError()

    def entity_configuration_endpoint(self, context, *args):
        jwk = JWK()

        data = {
            "exp": int((datetime.now() + timedelta(milliseconds=self.token_exp_delta)).timestamp()),
            "iat": int(datetime.now().timestamp()),
            "iss": self.client_id,
            "sub": self.client_id,
            "jwks": {
                "keys": [jwk.export_public()]
            },
            "metadata": {
                "wallet_relying_party": self.config['wallet_relying_party']
            }
        }

        jwshelper = JWSHelper(jwk, alg=self.default_sign_alg)

        return Response(
            jwshelper.sign(
                plain_dict=data,
                protected={
                    "alg": self.default_sign_alg,
                    "kid": jwk.jwk["kid"],
                    "typ": "entity-statement+jwt"
                }
            ),
            status=200
        )

    def pre_request_endpoint(self, context, *args):
        payload = {'client_id': self.client_id,
                   'request_uri': self.complete_request_url}
        query = urlencode(payload, quote_via=quote_plus)
        response = base64.b64encode(
            bytes(f'eudiw://authorize?{query}', 'UTF-8'))

        return Response(
            response,
            status=200,
            content="text/json; charset=utf8"
        )

    def redirect_endpoint(self, context, *args):
        jwk = JWK()

        helper = JWSHelper(jwk, alg=self.default_sign_alg)
        jwt = helper.sign({
            "jti": str(uuid.uuid4()),
            "htm": "GET",
            "htu": self.complete_request_url,
            "iat": int(datetime.now().timestamp()),
            "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        })

        response = {"request": jwt}

        return Response(
            json.dumps(response),
            status=200,
            content="text/json; charset=utf8"
        )

    def request_endpoint(self, context, *args):
        jwk = JWK()

        helper = JWSHelper(jwk, alg=self.default_sign_alg)
        jwt = helper.sign({
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
        })

        response = {"response": jwt}

        return Response(
            json.dumps(response),
            status=200,
            content="text/json; charset=utf8"
        )

    def authn_request(self, context, entity_id):
        """
        Do an authorization request on idp with given entity id.
        This is the start of the authorization.

        :type context: satosa.context.Context
        :type entity_id: str
        :rtype: satosa.response.Response

        :param context: The current context
        :param entity_id: Target IDP entity id
        :return: response to the user agent
        """
        breakpoint()
        pass
        
        
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
        return Response(result, content="text/json; charset=utf8", status=403)

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
