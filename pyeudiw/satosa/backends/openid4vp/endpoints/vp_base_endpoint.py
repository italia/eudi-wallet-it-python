from typing import Any, Callable

from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.response import Response

from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.utils.validation import (
    validate_oauth_client_attestation_pop,
    validate_oauth_client_attestation
)
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
            converter: AttributeMapper | None = None):
        """
        Initialize the OpenID4VCI endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
            auth_callback (Callable, optional): A callback function to handle authorization requests. Defaults to None.
        """
        super().__init__(config, internal_attributes, base_url, name, auth_callback, converter)

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

        # Initialize the database engine
        self.db_engine = DBEngine(self.storage_settings)

    def wallet_attestation_validation(self, context: Context):
        if self._wallet_attestation_required:
            try:
                validate_oauth_client_attestation_pop(
                    context,
                    self._client_attestation_pop_signing_alg_values_supported
                )
                validate_oauth_client_attestation(
                    context,
                    self._client_attestation_signing_alg_values_supported
                )
                return None
            except InvalidRequestException as e:
                self._log_error(
                    e.__class__.__name__,
                    f"Error during OAuth client attestation validation: {e}"
                )
                return self._handle_400(context, str(e), e)
        else:
            return None

    @property
    def _wallet_attestation_required(self) -> bool:
        """
        Check if wallet attestation is required.
        Returns:
            bool: True if wallet_attestation is required, False otherwise. Defaults to True.
        """
        return self.config.get("security", {}).get("wallet_attestation_required", True)

    @property
    def _client_attestation_signing_alg_values_supported(self) -> list[str]:
        """
        Get the supported signing algorithms for client attestation.
        Returns:
            list: A list of supported signing algorithms.
        """
        return self.config.get("metadata", {}).get("client_attestation_signing_alg_values_supported")

    @property
    def _client_attestation_pop_signing_alg_values_supported(self) -> list[str]:
        """
        Get the supported signing algorithms for client attestation with proof of possession.
        Returns:
            list: A list of supported signing algorithms.
        """
        return self.config.get("metadata", {}).get("client_attestation_pop_signing_alg_values_supported")