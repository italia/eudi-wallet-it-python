from typing import List, Dict, Optional, Union

from pydantic import BaseModel


class OauthAuthorizationServerMetadata(BaseModel):
    response_types_supported: List[str]
    response_modes_supported: List[str]
    code_challenge_methods_supported: List[str]
    scopes_supported: List[str]

class CredentialConfiguration(BaseModel):
    id: str

class OpenidCredentialIssuerMetadata(BaseModel):
    credential_configurations_supported: dict
    authorization_servers: Optional[List[Optional[str]]] = None
    credential_issuer: Optional[str]

class Metadata(BaseModel):
    oauth_authorization_server: OauthAuthorizationServerMetadata
    openid_credential_issuer: OpenidCredentialIssuerMetadata