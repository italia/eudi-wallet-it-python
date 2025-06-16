import json

from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.tools.content_type import APPLICATION_JSON, ENTITY_STATEMENT_JWT
from pyeudiw.tools.utils import exp_from_now, iat_now


class MetadataHandler(BaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the OpenID4VCI metadata endpoint class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)
        self.metadata_jwks = config.get("metadata_jwks", [])

    @property
    def authority_hints(self):
        return (
            self.config.get("trust", {})
            .get("federation", {})
            .get("config", {})
            .get("authority_hints", [])
        )

    def _ensure_credential_issuer(self, metadata: dict, metadata_key: str, issuer_key:str):
        metadata_val = metadata.get(metadata_key)
        if metadata_val and isinstance(metadata_val, dict) and not metadata_val.get(issuer_key):
            metadata_val[issuer_key] = self._backend_url

    @property
    def metadata(self) -> dict:
        metadata = self.config.get("metadata", {})
        [
            self._ensure_credential_issuer(metadata, metadata_key, issuer_key)
            for mapping_config in self.config_utils.get_credential_configurations().ensure_credential_issuer
            if isinstance(mapping_config, dict)
            for metadata_key, issuer_key in mapping_config.items()
        ]
        return metadata

    @property
    def entity_configuration_as_dict(self) -> dict:
        """Returns the entity configuration as a dictionary."""
        ec_payload = {
            "exp": exp_from_now(minutes=self.config_utils.get_credential_configurations().entity_configuration_exp),
            "iat": iat_now(),
            "iss": self.entity_id,
            "sub": self.entity_id,
            "jwks": {"keys": self.metadata_jwks},
            "metadata": self.metadata,
            "authority_hints": self.authority_hints,
        }
        return ec_payload

    @property
    def entity_configuration(self) -> str:
        """
        Returns the entity configuration as a JWT.

        :return: The entity configuration
        :rtype: str
        """
        data = self.entity_configuration_as_dict
        _jwk = self.metadata_jwks[0]
        jwshelper = JWSHelper(_jwk)
        return jwshelper.sign(
            protected={
                "alg": self.config_utils.get_credential_configurations().entity_default_sig_alg,
                "kid": _jwk["kid"],
                "typ": "entity-statement+jwt",
            },
            plain_dict=data,
        )

    def endpoint(self, context: Context) -> Response:
        """
        Handle request to the metadata endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        is_json = context.qs_params.get("format", "") == "json"
        return Response(
            json.dumps(self.entity_configuration_as_dict) if is_json else self.entity_configuration,
            status="200",
            content=APPLICATION_JSON if is_json else ENTITY_STATEMENT_JWT
        )
