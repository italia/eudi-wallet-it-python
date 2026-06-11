from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, model_validator


class OauthAuthorizationServerMetadata(BaseModel):
    response_types_supported: Optional[List[str]] = None
    response_modes_supported: Optional[List[str]] = None
    code_challenge_methods_supported: Optional[List[str]] = None
    scopes_supported: Optional[List[str]] = None
    dpop_signing_alg_values_supported: Optional[List[str]] = None
    client_attestation_pop_signing_alg_values_supported: Optional[List[str]] = None
    client_attestation_signing_alg_values_supported: Optional[List[str]] = None


class CredentialConfigurationFormatEnum(Enum):
    SD_JWT = "dc+sd-jwt"  # nosec B105
    MSO_MDOC = "mso_mdoc"  # nosec B105


class CredentialConfiguration(BaseModel):
    id: str
    format: str
    scope: str
    doctype: Optional[str] = None
    vct: Optional[str] = None
    cryptographic_binding_methods_supported: Optional[List[str]] = None
    credential_signing_alg_values_supported: Optional[List[str]] = None
    proof_types_supported: Optional[dict] = None
    credential_metadata: Optional[dict] = None
    schema_id: Optional[str] = None
    authentic_sources: Optional[dict] = None

    @model_validator(mode='after')
    def check_id_type(self) -> 'CredentialConfiguration':
        if self.format == CredentialConfigurationFormatEnum.SD_JWT.value:
            if not self.vct: raise ValueError(f"vct field mandatory for credential format: {self.format}")
        elif self.format == CredentialConfigurationFormatEnum.MSO_MDOC.value:
            if not self.doctype: raise ValueError(f"doctype field mandatory for credential format: {self.format}")
        return self

    @staticmethod
    def map(id: str, config_dict: dict):
        return CredentialConfiguration(
            id=id,
            format=config_dict["format"],
            scope=config_dict["scope"],
            doctype=config_dict.get("doctype"),
            vct=config_dict.get("vct"),
            cryptographic_binding_methods_supported=config_dict.get("cryptographic_binding_methods_supported"),
            credential_signing_alg_values_supported=config_dict.get("credential_signing_alg_values_supported"),
            proof_types_supported=config_dict.get("proof_types_supported"),
            credential_metadata=config_dict.get("credential_metadata"),
            schema_id=config_dict.get("schema_id"),
            authentic_sources=config_dict.get("authentic_sources")
        )


class OpenidCredentialIssuerMetadata(BaseModel):
    credential_configurations_supported: Optional[dict] = None
    authorization_servers: Optional[List[Optional[str]]] = None
    credential_issuer: Optional[str]


class Metadata(BaseModel):
    oauth_authorization_server: Optional[OauthAuthorizationServerMetadata] = None
    openid_credential_issuer: Optional[OpenidCredentialIssuerMetadata] = None
