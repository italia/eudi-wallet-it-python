from typing import List, Literal

from pydantic import BaseModel, HttpUrl

from pyeudiw.jwk.schema import JwksSchema
from pyeudiw.openid4vp.schemas.federation_entity import FederationEntity
from pyeudiw.openid4vp.schemas.wallet_relying_party import WalletRelyingParty


class EntityConfigurationHeader(BaseModel):
    alg: str
    kid: str
    typ: Literal["entity-statement+jwt"]


class EntityConfigurationMetadataSchema(BaseModel):
    wallet_relying_party: WalletRelyingParty
    federation_entity: FederationEntity


class EntityConfigurationPayload(BaseModel):
    iat: int
    exp: int
    iss: HttpUrl
    sub: HttpUrl
    jwks: JwksSchema
    metadata: EntityConfigurationMetadataSchema
    authority_hints: List[HttpUrl]
