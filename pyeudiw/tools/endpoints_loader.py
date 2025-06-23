from typing import Callable, Any
from pyeudiw.tools.utils import get_dynamic_class
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.attribute_mapping import AttributeMapper



class EndpointsLoader:
    """
    A dynamic backend/frontend module.
    """

    def __init__(
            self,
            config: dict[str, dict[str, str] | list[str]],
            internal_attributes: dict[str, dict[str, str | list[str]]],
            base_url: str,
            name: str,
            auth_callback_func: Callable[[Context, InternalData], Response],
            converter: AttributeMapper | None = None
    ):
        """
        Create a backend/frontend dynamically.
        :param config: Configuration parameters for the module.
        :type config: dict[str, dict[str, str] | list[str]]
        :param base_url: base url of the service
        :type base_url: str
        :param name: name of the plugin
        :type name: str

        :returns: The class instance
        :rtype: object
        """

        endpoints: dict[str, Any] | None = config.get("endpoints", None)

        if not endpoints:
            raise ValueError("No endpoints configured in the OpenID4VCI config")
        
        if not isinstance(endpoints, dict):
            raise ValueError("Endpoints configuration must be a dictionary")

        endpoint_instances = {}
        for e in endpoints.values():
            if (
                    isinstance(e, dict)
                    and e.get("module", None)
                    and e.get("class", None)
            ):
                endpoint_class = get_dynamic_class(e["module"], e["class"])
                endpoint_instances[e["path"].lstrip("/")] = endpoint_class(config, internal_attributes, base_url, name, auth_callback_func, converter)

        self.endpoint_instances = endpoint_instances

