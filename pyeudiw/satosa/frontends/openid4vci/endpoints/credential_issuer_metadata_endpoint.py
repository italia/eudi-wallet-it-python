from satosa.context import Context

from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import (
    VCIBaseEndpoint,
)
from pyeudiw.satosa.utils.response import JsonResponse


class CredentialIssuerMetadataHandler(VCIBaseEndpoint):

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        *args
    ):
        """
        Initialize the OpenID4VCI metadata endpoint class.

        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """

        super().__init__(config, internal_attributes, base_url, name)

        if not self.config.get("metadata", {}).get("openid_credential_issuer"):
            raise ValueError(
                "Missing 'openid_credential_issuer' in metadata configuration."
            )

    @property
    def metadata(self) -> dict:
        metadata = self.config.get("metadata", {})
        return metadata

    @property
    def openid_credential_issuer_metadata_as_dict(self) -> dict:
        """Returns the entity configuration as a dictionary."""

        ec_payload = self.metadata.get("openid_credential_issuer", {})
        for k in ec_payload: #automatically add <base_url>/<name> if only path was specified in config
            if "endpoint" in k and "http" not in ec_payload[k]:
                ec_payload[k] = self._backend_url + ec_payload[k]
        return ec_payload

    def endpoint(self, context: Context) -> JsonResponse:
        """
        Handle request to the metadata endpoint.

        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """

        return JsonResponse(
            message=self.openid_credential_issuer_metadata_as_dict,
            status="200",
        )
