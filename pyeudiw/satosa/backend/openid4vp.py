import logging
from typing import Callable

from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response

from satosa.backends.base import BackendModule
from pyeudiw.tools.endpoints_loader import EndpointsLoader

logger = logging.getLogger(__name__)

class OpenID4VPBackend(BackendModule):
    def __init__(
            self,
            auth_req_callback_func: Callable[[Context, InternalData], Response],
            internal_attributes: dict[str, dict[str, str | list[str]]],
            config: dict[str, dict[str, str] | list[str]],
            base_url: str,
            name: str,
        ) -> None:
        """
        Initialize the OpenID4VP backend module.
        
        :param auth_req_callback_func: Function to handle authentication requests.
        :param internal_attributes: Internal attributes mapping.
        :param config: Configuration dictionary for the backend.
        :param base_url: Base URL for the backend.
        :param name: Name of the backend module.
        """
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.config = config
        self.base_url = base_url
        self.name = name

    def register_endpoints(self, **kwargs):
        """
        See super class satosa.backends.base.BackendModule
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        el = EndpointsLoader(
            self.config, self.internal_attributes, self.base_url, self.name, self.auth_callback_func, self.converter)
        url_map = []
        for path, inst in el.endpoint_instances.items():
            url_map.append((f"{self.name}/{path}", inst))

        logger.debug(f"Loaded OpenID4VP endpoints: {url_map}")
        return url_map
