import json
import logging
import base64

from urllib.parse import urlencode, quote_plus
from satosa.response import Response
from satosa.backends.base import BackendModule

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
        self.error_page = config['error_url']

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
        response = '{"request": "ewogICJ0eXAiOiAiZHBvcCtqd3QiLAogICJhbGciOiAiRVMyNTYiLAogICJqd2siOiB7CiAgICAia3R5IjogIkVDIiwKICAgICJ4IjogImw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLAogICAgInkiOiAiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsCiAgICAiY3J2IjogIlAtMjU2IgogIH0KfQ.ewogICJqdGkiOiAiZjQ3Yzk2YTEtZjkyOC00NzY4LWFhMzAtZWYzMmRjNzhhYTY5IiwKICAiaHRtIjogIkdFVCIsCiAgImh0dSI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnL3JlcXVlc3RfdXJpIiwKICAiaWF0IjogMTU2MjI2MjYxNiwKICAiYXRoIjogImZVSHlPMnIyWjNEWjUzRXNOcldCYjB4V1hvYU55NTlJaUtDQXFrc21RRW8iCn0"}'
        return Response(
            response,
            status="200 OK",
            content="text/json; charset=utf8"
        )

    def request_endpoint(self, context, *args):
        response = '{"response": "ewogICJhbGciOiAiRVMyNTYiLAogICJ0eXAiOiAiSldUIiwKICAia2lkIjogImUwYmJmMmYxLThjM2EtNGVhYi1hOGFjLTJlOGYzNGRiOGE0NyIKfQ.ewogICJpc3MiOiAiaHR0cHM6Ly93YWxsZXQtcHJvdmlkZXIuZXhhbXBsZS5vcmcvaW5zdGFuY2UvdmJlWEprc000NXhwaHRBTm5DaUc2bUN5dVU0amZHTnpvcEd1S3ZvZ2c5YyIsCiAgImp0aSI6ICIzOTc4MzQ0Zi04NTk2LTRjM2EtYTk3OC04ZmNhYmEzOTAzYzUiLAogICJhdWQiOiAiaHR0cHM6Ly92ZXJpZmllci5leGFtcGxlLm9yZy9jYWxsYmFjayIsCiAgImlhdCI6IDE1NDE0OTM3MjQsCiAgImV4cCI6IDE1NzMwMjk3MjMsCiAgIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsCiAgInZwIjogIjxTRC1KV1Q-fjxEaXNjbG9zdXJlIDE-fjxEaXNjbG9zdXJlIDI-fi4uLn48RGlzY2xvc3VyZSBOPiIKfQ"}'
        return Response(
            response,
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
