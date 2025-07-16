import json

from satosa.context import Context
from satosa.response import Response

from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import VCIBaseEndpoint
from pyeudiw.tools.content_type import APPLICATION_JSON


class CredentialIssuerMetadataHandler(VCIBaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str, *args):
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
            raise ValueError("Missing 'openid_credential_issuer' in metadata configuration.")

    @property
    def metadata(self) -> dict:
        metadata = self.config.get("metadata", {})
        return metadata

    @property
    def entity_configuration_as_dict(self) -> dict:
        """Returns the entity configuration as a dictionary."""
        ec_payload = self.metadata.get("openid_credential_issuer", {})
        return ec_payload

    def endpoint(self, context: Context) -> Response:
        """
        Handle request to the metadata endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        return Response(
            json.dumps(self.entity_configuration_as_dict),
            status="200",
            content=APPLICATION_JSON
        )