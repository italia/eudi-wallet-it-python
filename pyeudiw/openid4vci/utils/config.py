from typing import Any, List, Dict

from pydantic import BaseModel


class OauthAuthorizationServerMetadata(BaseModel):
    response_types_supported: List[str]
    response_modes_supported: List[str]
    code_challenge_methods_supported: List[str]
    scopes_supported: List[str]

class CredentialConfiguration(BaseModel):
    id: str

class OpenidCredentialIssuerMetadata(BaseModel):
    credential_configurations_supported: Dict[str, CredentialConfiguration]
    authorization_servers: List[str]
    credential_issuer: str


class Metadata(BaseModel):
    oauth_authorization_server: OauthAuthorizationServerMetadata
    openid_credential_issuer: OpenidCredentialIssuerMetadata

class Jwt(BaseModel):
    default_exp: int

class Config(BaseModel):
    jwt: Jwt
    metadata: Metadata

    def __init__(self, config: dict[str, dict[str, str] | list[str]], **data: Any):
        super().__init__(**data)
        self.config = config

    def get_jwt_default_exp(self) -> int:
        return self.jwt.default_exp

    def get_oauth_authorization_server(self) -> OauthAuthorizationServerMetadata:
        return self.metadata.oauth_authorization_server

    def get_openid_credential_issuer(self) -> OpenidCredentialIssuerMetadata:
        return self.metadata.openid_credential_issuer

    def get_credential_configurations_supported(self) -> Dict[str, CredentialConfiguration]:
        return self.get_openid_credential_issuer().credential_configurations_supported