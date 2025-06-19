from typing import Optional, List, Dict

from pydantic import BaseModel, Field

from pyeudiw.satosa.schemas.credential_specification import CredentialSpecificationConfig


class CredentialConfigurationsConfig(BaseModel):
    """
        Configuration model for credential presentation handling.
    """
    lookup_source: str
    ensure_credential_issuer: Optional[List[Dict[str, str]]] = Field(default_factory=lambda: [
        {"oauth_authorization_server": "issuer"},
        {"openid_credential_issuer": "credential_issuer"},
    ])
    credential_specification: Optional[Dict[str, CredentialSpecificationConfig]] = None
