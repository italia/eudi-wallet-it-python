from satosa.context import Context
from satosa.response import Response

from .event_handler import EventHandlerInterface


class RequestHandlerInterface(EventHandlerInterface):
    """
    Interface for request handlers.
    """

    def request_endpoint(
        self, context: Context, *args: tuple
    ) -> Response:
        """
        This endpoint is called by the User-Agent/Wallet Instance to retrieve the signed signed Request Object.

        :type context: the context of current request
        :param context: the request context

        :return: a response containing the request object
        :rtype: satosa.response.Response
        """
        raise NotImplementedError
