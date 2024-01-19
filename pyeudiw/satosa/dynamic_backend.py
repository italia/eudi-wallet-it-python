from typing import Callable
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response

from pyeudiw.tools.utils import get_dynamic_class 

class DynamicBackend(type):
    """
    A metaclass that allows to create a backend dynamically.
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

        dynamic_backend_conf = config.get("dynamic_backend", None)

        if dynamic_backend_conf is None:
            raise ValueError("No dynamic backend configuration specified.")
        
        base_backend_conf = dynamic_backend_conf.get("base_class", None)
        if base_backend_conf is None:
            raise ValueError("No base class specified.")
        
        base_backend = get_dynamic_class(base_backend_conf["module"], base_backend_conf["class"])


        response_handler_conf = dynamic_backend_conf.get("response_handler", None)
        if response_handler_conf is None:
            raise ValueError("No response handler specified.")
        
        response_handler = get_dynamic_class(response_handler_conf["module"], response_handler_conf["class"])

        request_backend_conf = dynamic_backend_conf.get("request_backend", None)
        if request_backend_conf is None:
            raise ValueError("No request backend specified.")
        
        request_backend = get_dynamic_class(request_backend_conf["module"], request_backend_conf["class"])

        new_class = type(dynamic_backend_conf["class_name"], (request_backend, response_handler, base_backend), {})

        return new_class.__new__(new_class, auth_callback_func, internal_attributes, config, base_url, name)