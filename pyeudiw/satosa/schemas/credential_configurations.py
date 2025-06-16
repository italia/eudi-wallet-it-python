from typing import Optional, List, Dict

from pydantic import BaseModel, Field


class CredentialConfigurationsConfig(BaseModel):
    """
        Configuration model for credential presentation handling.
    """
    lookup_source: str
    entity_configuration_exp: int
    entity_default_sig_alg: str
    ensure_credential_issuer: Optional[List[Dict[str, str]]] = Field(default_factory=lambda: [
        {"oauth_authorization_server": "issuer"},
        {"openid_credential_issuer": "credential_issuer"},
    ])
    credential_specification_template: Optional[str] = None
