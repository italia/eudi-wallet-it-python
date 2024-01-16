from .default.request_handler import DefaultRequestHandler
from .default.response_handler import DefaultResponseHandler
from .default.openid4vp_backend import DefaultOpenID4VPBackend


class OpenID4VPBackend(DefaultRequestHandler, DefaultResponseHandler, DefaultOpenID4VPBackend):
    """
    A backend module (acting as a OpenID4VP SP).
    """
    pass