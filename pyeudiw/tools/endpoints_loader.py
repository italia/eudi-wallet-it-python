from pyeudiw.tools.utils import get_dynamic_class


class EndpointsLoader:
    """
    A dynamic backend/frontend module.
    """

    def __init__(
            self,
            config: dict[str, dict[str, str] | list[str]],
            internal_attributes: dict[str, dict[str, str | list[str]]],
            base_url: str,
            name: str
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

        endpoints= config.get("endpoints", None)
        endpoint_instances = {}
        for e in endpoints.values():
            if (
                    isinstance(e, dict)
                    and e.get("module", None)
                    and e.get("class", None)
            ):
                endpoint_class = get_dynamic_class(e["module"], e["class"])
                endpoint_instances[e["path"].lstrip("/")] = endpoint_class(config, internal_attributes, base_url, name)

        self.endpoint_instances = endpoint_instances

