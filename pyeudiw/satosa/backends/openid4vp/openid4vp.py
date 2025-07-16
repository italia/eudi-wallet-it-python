import logging
from typing import Callable, Any

from satosa.backends.base import BackendModule
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response

from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.endpoints_loader import EndpointsLoader
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.trust.handler.interface import TrustHandlerInterface

logger = logging.getLogger(__name__)

class OpenID4VPBackend(BackendModule):
    def __init__(
            self,
            auth_req_callback_func: Callable[[Context, InternalData], Response],
            internal_attributes: dict[str, dict[str, str | list[str]]],
            config: dict[str, Any],
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

        if self.config["authorization"].get("client_id"):
            self.client_id = self.config["authorization"]["client_id"] 
        elif self.config["metadata"].get("client_id"):
            self.client_id = self.config["metadata"]["client_id"]
        else:
            self.client_id = f"{base_url}/{name}"

        self._backend_url = f"{base_url}/{name}"
        
        self.storage_settings = self.config.get("storage", {})
        if not self.storage_settings:
            raise ValueError(
                "Storage settings are not configured. Please check your configuration."
            )

        # Initialize the database engine
        self.db_engine = DBEngine(self.storage_settings)

        # This loads all the configured trust evaluation mechanisms
        trust_configuration = self.config.get("trust", {})
        trust_caching_mode = self.config.get("trust_caching_mode", "update_first")

        self.trust_evaluator = CombinedTrustEvaluator.from_config(
            trust_configuration, 
            self.db_engine, 
            default_client_id = self.client_id, 
            mode = trust_caching_mode
        )

        self.endpoints = {}

    def register_endpoints(self, **kwargs):
        """
        See super class satosa.backends.base.BackendModule
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        el = EndpointsLoader(
            self.config, self.internal_attributes, self.base_url, self.name, self.auth_callback_func, self.converter, self.trust_evaluator)
        
        url_map = []

        for path, inst in el.endpoint_instances.items():
            url_map.append((f"{self.name}/{path}", inst))


        metadata_map = self.trust_evaluator.build_metadata_endpoints(
            self.name, self._backend_url
        )

        url_map.extend(metadata_map)

        for path, inst in url_map:
            self.endpoints[f"{path.split('/')[-1].replace('-', '_').replace('$', '')}"] = inst
        
        logger.debug(f"Loaded OpenID4VP endpoints: {url_map}")
        return url_map
    
    def start_auth(self, context: Context, internal_request) -> Response:
        """
        This is the start up function of the backend authorization.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Response

        :param context: the request context
        :param internal_request: Information about the authorization request
        :return: response
        """
        pre_request_endpoint = self.endpoints.get("pre_request")
        if not pre_request_endpoint:
            raise ValueError("No pre-request endpoint configured in the OpenID4VP backend")

        return pre_request_endpoint(context)

    def get_trust_backend_by_class_name(self, class_name: str) -> TrustHandlerInterface | None:
        for i in self.trust_evaluator.handlers:
            if i.__class__.__name__ == class_name:
                return i
