from satosa.context import Context

from pyeudiw.satosa.backends.openid4vp.endpoints.vp_base_endpoint import (
    VPBaseEndpoint,
)
from pyeudiw.satosa.utils.response import JsonResponse


class JarIssuerMetadataHandler(VPBaseEndpoint):

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        *args,
        trust_evaluator=None,
        db_engine=None,
        **kwargs
    ):
        """
        Initialize the JAR issuer metadata endpoint handler.

        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
            trust_evaluator: Optional trust evaluator.
            db_engine: Optional shared database engine.
        """

        # Initialize base class - handles configuration and logging
        # We bypass the full VPBaseEndpoint initialization to avoid client_id validation
        # since this endpoint only returns metadata and doesn't process requests
        from pyeudiw.tools.base_endpoint import BaseEndpoint
        BaseEndpoint.__init__(
            self,
            config,
            internal_attributes,
            base_url,
            name,
            auth_callback=None,
            converter=None,
        )
        
        # Store the db_engine if provided
        self.db_engine = db_engine

        if not self.config.get("metadata_jwks"):
            raise ValueError(
                "Missing 'metadata_jwks' in configuration for JAR issuer metadata."
            )

    @property
    def jar_issuer_metadata_as_dict(self) -> dict:
        """
        Returns the JAR issuer metadata containing the JWK set.
        
        The JAR issuer endpoint returns the verifier's JWKS to allow
        wallets to verify authorization requests signed by this verifier.
        
        Returns:
            dict: Metadata containing JWKS in the format:
                {
                    "jwks": [list of JWK objects]
                }
        """

        jwks = self.config.get("metadata_jwks", [])
        
        return {
            "jwks": jwks
        }

    def endpoint(self, context: Context) -> JsonResponse:
        """
        Handle request to the JAR issuer metadata endpoint.

        This endpoint serves the verifier's JWKS so wallets can
        verify signatures on authorization requests issued by this verifier.

        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object with status 200 and the JWKS metadata.
        """

        return JsonResponse(
            message=self.jar_issuer_metadata_as_dict,
            status="200",
        )

