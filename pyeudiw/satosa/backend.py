from pyeudiw.satosa.default.openid4vp_backend import OpenID4VPBackend as OID4VP
from pyeudiw.satosa.default.request_handler import RequestHandler
from pyeudiw.satosa.default.response_handler import ResponseHandler

from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response

from typing import Callable

from pyeudiw.tools.utils import get_dynamic_class

class OpenID4VPBackend(RequestHandler, ResponseHandler, OID4VP):
    """
    A backend module (acting as a OpenID4VP SP).
    """
    def __new__(cls,
        auth_callback_func: Callable[[Context, InternalData], Response],
        internal_attributes: dict[str, dict[str, str | list[str]]],
        config: dict[str, dict[str, str] | list[str]],
        base_url: str,
        name: str
    ):
        """
        Create a backend dynamically.

        :param auth_callback_func: Callback should be called by the module after the authorization
        in the backend is done.
        :type auth_callback_func: Callable[[Context, InternalData], Response]
        :param internal_attributes: Mapping dictionary between SATOSA internal attribute names and
        the names returned by underlying IdP's/OP's as well as what attributes the calling SP's and
        RP's expects namevice.
        :type internal_attributes: dict[str, dict[str, str | list[str]]]
        :param config: Configuration parameters for the module.
        :type config: dict[str, dict[str, str] | list[str]]
        :param base_url: base url of the service
        :type base_url: str
        :param name: name of the plugin
        :type name: str

        :returns: The class instance
        :rtype: object
        """

        dynamic_backend_conf = config.get("endpoints", None)

        request_backend_conf = dynamic_backend_conf.get("request", None)

        tmp_bases = list(cls.__bases__)

        if isinstance(request_backend_conf, dict) \
            and request_backend_conf.get("module", None) \
            and request_backend_conf.get("class", None):
        
            request_backend = get_dynamic_class(
                request_backend_conf["module"],
                request_backend_conf["class"]
            )

            tmp_bases[0] = request_backend

        response_handler_conf = dynamic_backend_conf.get("response", None)

        if isinstance(response_handler_conf, dict) \
            and response_handler_conf.get("module", None) \
            and response_handler_conf.get("class", None):
        
            response_handler = get_dynamic_class(
                response_handler_conf["module"],
                response_handler_conf["class"]
            )

            tmp_bases[1] = response_handler

        cls.__bases__ = tuple(tmp_bases)
        obj = super(OpenID4VPBackend, cls).__new__(cls)

        return obj