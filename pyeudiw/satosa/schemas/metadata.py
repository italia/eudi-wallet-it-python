from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class OauthAuthorizationServerMetadata(BaseModel):
    response_types_supported: Optional[List[str]] = None
    response_modes_supported: Optional[List[str]] = None
    code_challenge_methods_supported: Optional[List[str]] = None
    scopes_supported: Optional[List[str]] = None

class CredentialConfigurationFormatEnum(Enum):
    SD_JWT = "dc+sd-jwt" #nosec B105
    MSO_MDOC = "mso_mdoc" #nosec B105

class CredentialConfiguration(BaseModel):
    id: str
    format: str
    scope: str

class OpenidCredentialIssuerMetadata(BaseModel):
    credential_configurations_supported: Optional[dict] = None
    authorization_servers: Optional[List[Optional[str]]] = None
    credential_issuer: Optional[str]

class Metadata(BaseModel):
    oauth_authorization_server: Optional[OauthAuthorizationServerMetadata] = None
    openid_credential_issuer: Optional[OpenidCredentialIssuerMetadata] = None