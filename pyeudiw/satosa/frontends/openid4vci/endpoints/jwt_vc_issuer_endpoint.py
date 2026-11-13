from satosa.context import Context

from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import (
    VCIBaseEndpoint,
)
from pyeudiw.satosa.utils.response import JsonResponse


class JwtVcIssuerMetadataHandler(VCIBaseEndpoint):

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        *args
    ):
        """
        Initialize the JWT-VC issuer metadata endpoint handler.

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
    def jwt_vc_issuer_metadata_as_dict(self) -> dict:
        """
        Returns the JWT-VC issuer metadata containing the JWK set.
        
        The JWT-VC issuer endpoint returns the issuer's JWKS to allow
        external parties to verify credentials issued by this system.
        
        Returns:
            dict: Metadata containing JWKS in the format:
                {
                    "jwks": [list of JWK objects]
                }
        """

        metadata = self.config.get("metadata", {})
        jwks = metadata.get("openid_credential_issuer", {}).get("jwks", [])
        
        return {
            "jwks": jwks
        }

    def endpoint(self, context: Context) -> JsonResponse:
        """
        Handle request to the JWT-VC issuer metadata endpoint.

        This endpoint serves the issuer's JWKS so external parties can
        verify signatures on credentials issued by this system.

        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object with status 200 and the JWKS metadata.
        """

        return JsonResponse(
            message=self.jwt_vc_issuer_metadata_as_dict,
            status="200",
        )
