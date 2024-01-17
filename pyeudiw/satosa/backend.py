from pyeudiw.satosa.default.openid4vp_backend import DefaultOpenID4VPBackend
from pyeudiw.satosa.default.request_handler import DefaultRequestHandler
from pyeudiw.satosa.default.response_handler import DefaultResponseHandler


class OpenID4VPBackend(DefaultRequestHandler, DefaultResponseHandler, DefaultOpenID4VPBackend):
    """
    A backend module (acting as a OpenID4VP SP).
    """
    pass