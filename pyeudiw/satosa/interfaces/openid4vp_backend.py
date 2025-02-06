from satosa.context import Context
from satosa.response import Response

from pyeudiw.satosa.utils.response import JsonResponse

from .event_handler import EventHandlerInterface


class OpenID4VPBackendInterface(EventHandlerInterface):
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
        raise NotImplementedError

    def request_endpoint(self, context: Context, *args) -> Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance to retrieve the signed signed Request Object.

        :type context: the context of current request
        :param context: the request context

        :return: a response containing the request object
        :rtype: satosa.response.Response
        """
        raise NotImplementedError

    def response_endpoint(self, context: Context, *args) -> JsonResponse:
        """
        This endpoint is called by the User-Agent/Wallet Instance after the user has been authenticated.

        :type context: the context of current request
        :param context: the request context
        :param args: the request arguments
        :type args: tuple

        :return: a json response containing the request object
        :rtype: JsonResponse
        """
        raise NotImplementedError

    def get_response_endpoint(self, context: Context) -> Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance to retrieve the response of the authentication.

        :param context: the request context
        :type context: satosa.context.Context

        :return: a response containing the response object with the authenctication status
        :rtype: Response
        """
        raise NotImplementedError

    def status_endpoint(self, context: Context) -> JsonResponse:
        """
        This endpoint is called by the User-Agent/Wallet Instance the url to the response endpoint to finalize the process.

        :param context: the request context
        :type context: satosa.context.Context

        :return: a json response containing the status and the url to get the response
        :rtype: JsonResponse
        """
        raise NotImplementedError
