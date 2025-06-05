from typing import Dict, Any

from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.satosa.schemas.config import PyeudiwFrontendConfig
from pyeudiw.satosa.schemas.metadata import (
    OauthAuthorizationServerMetadata,
    OpenidCredentialIssuerMetadata,
    CredentialConfiguration
)

class PyeudiwFrontendConfigUtils:
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

    def get_credential_configurations_supported(self) -> Dict[str, CredentialConfiguration]:
        ccs = self.get_openid_credential_issuer().credential_configurations_supported
        return {
            k: CredentialConfiguration(id=k)
            for k, v in ccs.items()
        }