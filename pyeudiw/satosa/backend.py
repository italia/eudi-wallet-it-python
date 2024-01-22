from pyeudiw.satosa.default.openid4vp_backend import OpenID4VPBackend as OID4VP
from pyeudiw.satosa.default.request_handler import RequestHandler
from pyeudiw.satosa.default.response_handler import ResponseHandler


class OpenID4VPBackend(RequestHandler, ResponseHandler, OID4VP):
    """
    A backend module (acting as a OpenID4VP SP).
    """
    pass