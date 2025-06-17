from typing import Dict, Any

from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.openid4vci.models.config import PyeudiwFrontendConfig
from pyeudiw.satosa.schemas.credential_configurations import CredentialConfigurationsConfig
from pyeudiw.satosa.schemas.metadata import (
    OauthAuthorizationServerMetadata,
    OpenidCredentialIssuerMetadata,
    CredentialConfiguration
)


class Openid4VciFrontendConfigUtils:
    """
        Utility class to simplify access to OpenID4VCI frontend configuration data.

        This class wraps the frontend configuration and exposes convenient
        methods to retrieve JWT settings, OAuth authorization server metadata,
        OpenID credential issuer metadata, and supported credential configurations.

        Args:
            config (Any): The configuration object or dictionary.
                          If not already an instance of `PyeudiwFrontendConfig`,
                          it will be parsed into one.
    """
    def __init__(self, config: Any):
        if isinstance(config, PyeudiwFrontendConfig):
            self.config = config
        else:
            self.config = PyeudiwFrontendConfig(**config)

    def get_jwt(self) -> JWTConfig:
        return self.config.jwt

    def get_jwt_default_sig_alg(self) -> str:
        return self.config.jwt.default_sig_alg

    def get_oauth_authorization_server(self) -> OauthAuthorizationServerMetadata:
        return self.config.metadata.oauth_authorization_server

    def get_openid_credential_issuer(self) -> OpenidCredentialIssuerMetadata:
        return self.config.metadata.openid_credential_issuer

    def get_credential_configurations_supported(self) -> Dict[str, CredentialConfiguration] | None:
        ccs = self.get_openid_credential_issuer().credential_configurations_supported
        if not ccs:
            return None
        return {
            k: CredentialConfiguration(id=k)
            for k, v in ccs.items()
        }

    def get_credential_configurations(self) -> CredentialConfigurationsConfig:
        return self.config.credential_configurations
