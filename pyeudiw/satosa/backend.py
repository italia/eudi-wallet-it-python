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
        super().__init__(auth_callback_func, internal_attributes, base_url, name)

        self.entity_configuration_url = config['entity_configuration_endpoint']
        self.pre_request_url = config['pre_request_endpoint']
        self.redirect_url = config['redirect_endpoint']
        self.request_url = config['request_endpoint']
        self.error_url = config['error_url']

        self.client_id = config['wallet_relying_party']['client_id']
        self.complete_redirect_url = config['wallet_relying_party']['redirect_uris'][0]
        self.complete_request_url = config['wallet_relying_party']['request_uris'][0]

        self.qr_settings = config['qr_code_settings']

    def register_endpoints(self):
        """
        Creates a list of all the endpoints this backend module needs to listen to. In this case
        it's the authentication response from the underlying OP that is redirected from the OP to
        the proxy.
        :rtype: Sequence[(str, Callable[[satosa.context.Context], satosa.response.Response]]
        :return: A list that can be used to map the request to SATOSA to this endpoint.
        """
        url_map = []
        url_map.append(
            (f"^{self.entity_configuration_url.lstrip('/')}$", self.entity_configuration))
        url_map.append(
            (f"^{self.pre_request_url.lstrip('/')}$", self.pre_request_endpoint))
        url_map.append(
            (f"^{self.redirect_url.lstrip('/')}$", self.redirect_endpoint))
        url_map.append(
            (f"^{self.request_url.lstrip('/')}$", self.request_endpoint))
        return url_map

    def entity_configuration(self, context, *args):
        return Response(
            status="200 OK"
        )

    def pre_request_endpoint(self, context, *args):
        payload = {'client_id': self.client_id,
                   'request_uri': self.complete_request_url}
        query = urlencode(payload, quote_via=quote_plus)
        response = base64.b64encode(
            bytes(f'eudiw://authorize?{query}', 'UTF-8'))

        return Response(
            response,
            status="200 OK"
        )

    def redirect_endpoint(self, context, *args):
        jwk = JWK({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
                "crv": "P-256"
            }
        })

        helper = JWSHelper(jwk)
        jwt = helper.sign({
            "jti": "f47c96a1-f928-4768-aa30-ef32dc78aa69",
            "htm": "GET",
            "htu": "https://verifier.example.org/request_uri",
            "iat": 1562262616,
            "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        },
            "RS256",
        )

        response = {"request": jwt}

        return Response(
            json.dumps(response),
            status="200 OK",
            content="text/json; charset=utf8"
        )

    def request_endpoint(self, context, *args):
        jwk = JWK({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
                "crv": "P-256"
            }
        })

        helper = JWSHelper(jwk)
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
        },
            "RS256",
        )

        response = {"response": jwt}

        return Response(
            json.dumps(response),
            status="200 OK",
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
        return Response(result, content="text/json; charset=utf8", status="403 Forbidden")

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
