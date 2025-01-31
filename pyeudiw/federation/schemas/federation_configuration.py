from pydantic import BaseModel, HttpUrl

from pyeudiw.federation.schemas.openid_credential_verifier import \
    SigningAlgValuesSupported
from pyeudiw.jwk.schemas.public import JwkSchema


class FederationEntityMetadata(BaseModel):
    organization_name: str
    homepage_uri: HttpUrl
    policy_uri: HttpUrl
    tos_uri: HttpUrl
    logo_uri: HttpUrl


class FederationConfig(BaseModel):
    metadata_type: str
    authority_hints: list[HttpUrl]
    trust_anchors: list[HttpUrl]
    default_sig_alg: SigningAlgValuesSupported
    federation_entity_metadata: FederationEntityMetadata
    federation_jwks: list[JwkSchema]
