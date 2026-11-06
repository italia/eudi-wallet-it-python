from typing import Any, Callable

from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.response import Response

from pyeudiw.satosa.backends.openid4vp.authorization_request import prefixed_client_id
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.base_endpoint import BaseEndpoint


class VPBaseEndpoint(BaseEndpoint):

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        auth_callback: Callable[[Context, Any], Response] | None = None,
        converter: AttributeMapper | None = None,
        trust_evaluator=None,
        db_engine=None,
    ):
        """
        Initialize the OpenID4VCI endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
            auth_callback (Callable, optional): A callback function to handle authorization requests. Defaults to None.
            trust_evaluator: Optional trust evaluator (used by some subclasses).
            db_engine: Optional shared DBEngine; if None, a new one is created (reuse from backend to limit MongoClient count).
        """
        super().__init__(
            config, internal_attributes, base_url, name, auth_callback, converter
        )

        self.client_id = prefixed_client_id(self.config)
        self.storage_settings = self.config.get("storage", {})
        if not self.storage_settings:
            raise ValueError(
                "Storage settings are not configured. Please check your configuration."
            )

        self.db_engine = (
            db_engine if db_engine is not None else DBEngine(self.storage_settings)
        )

    def attested_https_uri(
        self, metadata_key: str, endpoint_name: str, default_path: str
    ) -> str:
        metadata = self.config.get("metadata") or {}
        values = metadata.get(metadata_key) or []
        if isinstance(values, str) and values.startswith("https://"):
            return values
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and value.startswith("https://"):
                    return value
        endpoint = (self.config.get("endpoints") or {}).get(endpoint_name)
        if isinstance(endpoint, str) and endpoint:
            path = endpoint
        elif isinstance(endpoint, dict) and endpoint.get("path"):
            path = endpoint["path"]
        else:
            path = default_path
        if not str(path).startswith("/"):
            path = f"/{path}"
        return f"{self._backend_url}{path}"
