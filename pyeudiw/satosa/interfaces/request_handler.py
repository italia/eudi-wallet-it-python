from satosa.context import Context
from satosa.response import Redirect
from pyeudiw.satosa.utils.response import JsonResponse
from .event_handler import EventHandlerInterface


class RequestHandlerInterface(EventHandlerInterface):
    """
    Interface for request handlers.
    """
    def request_endpoint(self, context: Context, *args: tuple) -> Redirect | JsonResponse:
        """
        This endpoint is called by the User-Agent/Wallet Instance to retrieve the signed signed Request Object.

        :type context: the context of current request
        :param context: the request context

        :return: a redirect to the User-Agent/Wallet Instance, if is in same device flow, or a json response if is in cross device flow.
        :rtype: Redirect | JsonResponse
        """
        raise NotImplementedError