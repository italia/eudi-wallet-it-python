from satosa.context import Context
from ..impl.response import JsonResponse
from .event_handler import EventHandlerInterface

class ResponseHandlerInterface(EventHandlerInterface):
    """
    Interface for response handlers.
    """
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