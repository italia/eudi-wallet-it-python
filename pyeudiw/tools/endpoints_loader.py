from typing import Callable, Any
from pyeudiw.tools.utils import get_dynamic_class
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.attribute_mapping import AttributeMapper
from pyeudiw.trust.dynamic import CombinedTrustEvaluator



class EndpointsLoader:
    """
    A dynamic backend/frontend module.
    """

    def __init__(
            self,
            config: dict[str, Any],
            internal_attributes: dict[str, dict[str, str | list[str]]],
            base_url: str,
            name: str,
            auth_callback_func: Callable[[Context, InternalData], Response] | None = None,
            converter: AttributeMapper | None = None,
            trust_evaluator: CombinedTrustEvaluator | None = None
    ):
        """
        Create a backend/frontend dynamically.
        :param config: Configuration parameters for the module.
        :type config: dict[str, Any]
        :param internal_attributes: Internal attributes mapping.
        :type internal_attributes: dict[str, dict[str, str | list[str]]]
        :param base_url: base url of the service
        :type base_url: str
        :param name: name of the plugin
        :type name: str
        :param auth_callback_func: Function to handle authentication requests.
        :type auth_callback_func: Callable[[Context, InternalData], Response] | None
        :param converter: An instance of AttributeMapper for attribute conversion.
        :type converter: AttributeMapper | None

        :returns: The class instance
        :rtype: object
        """

        endpoints = config.get("endpoints", None)

        if not endpoints:
            raise ValueError("No endpoints configured in the OpenID4VCI config")
        
        if not isinstance(endpoints, dict):
            raise ValueError("Endpoints configuration must be a dictionary")
        
        endpoint_instances = {}
        for e in endpoints.values():
            module = e.get("module", None)
            class_name = e.get("class", None)
            path = e.get("path", None)

            if module and class_name and path:
                endpoint_class = get_dynamic_class(module, class_name)
                endpoint_instances[path.lstrip("/")] = endpoint_class(
                    config,
                    internal_attributes,
                    base_url,
                    name,
                    auth_callback_func,
                    converter,
                    trust_evaluator
                )

        self.endpoint_instances = endpoint_instances

