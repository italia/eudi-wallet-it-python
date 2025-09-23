import json

from satosa.context import Context
from cryptojwt.jwk.jwk import key_from_jwk_dict
from pyeudiw.satosa.utils.response import JsonResponse

from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import VCIBaseEndpoint


class JWTVCIssuerMetadataHandler(VCIBaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str, *args):
        """
        Initialize the OpenID4VCI jwt vc metadata endpoint class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)

        if not self.config.get("metadata_jwks", {}):
            raise ValueError("Missing 'metadata_jwks' in configuration.")

        self.credential_issuer = self.config.get("metadata", {}).get("openid_credential_issuer", {}).get("credential_issuer", "")
        if not self.credential_issuer:
            raise ValueError("Missing 'credential_issuer' in metadata configuration.")

    @property
    def metadata_jwks(self) -> dict:
        metadata = self.config.get("metadata_jwks", {})
        return metadata

    @property
    def jwt_vc_issuer_metadata_as_dict(self) -> dict:
        """Returns the JWT VC issuer metadata as a dictionary."""
        metadata_jwks = [key_from_jwk_dict(jwk).serialize(private=False) for jwk in self.metadata_jwks]
        return {
            "issuer": self.credential_issuer,
            "jwks": {
                "keys": metadata_jwks
            }
        }

    def endpoint(self, context: Context) -> JsonResponse:
        """
        Handle request to the metadata endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        return JsonResponse(
            message=self.jwt_vc_issuer_metadata_as_dict,
            status="200",
        )