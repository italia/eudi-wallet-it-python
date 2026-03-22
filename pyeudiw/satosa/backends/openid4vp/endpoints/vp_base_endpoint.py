from typing import Any, Callable

from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.response import Response

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

        if self.config["authorization"].get("client_id"):
            self.client_id = self.config["authorization"]["client_id"]
        elif self.config["metadata"].get("client_id"):
            self.client_id = self.config["metadata"]["client_id"]
        else:
            self.client_id = f"{base_url}/{name}"

        self.storage_settings = self.config.get("storage", {})
        if not self.storage_settings:
            raise ValueError(
                "Storage settings are not configured. Please check your configuration."
            )

        # Reuse shared db_engine from backend when provided to avoid multiple MongoClient instances per backend.
        self.db_engine = (
            db_engine if db_engine is not None else DBEngine(self.storage_settings)
        )
