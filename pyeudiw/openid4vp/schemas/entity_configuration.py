from typing import List, Literal

from pydantic import BaseModel, HttpUrl, field_validator
from pydantic_core.core_schema import FieldValidationInfo

from pyeudiw.jwk.schema import JwksSchema
from pyeudiw.openid4vp.schemas.federation_entity import FederationEntity
from pyeudiw.openid4vp.schemas.wallet_relying_party import WalletRelyingParty


_default_supported_algorithms = [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
]


def _check_alg(alg: str, info: FieldValidationInfo):
    if not info.context:
        supported_algorithms = _default_supported_algorithms
    else:
        supported_algorithms = info.context.get(
            "supported_algorithms", _default_supported_algorithms)

    if alg not in supported_algorithms:
        raise ValueError(f"Unsupported algorithm: {alg}.\n  "
                         f"Supported algorithms: {supported_algorithms}.\n")


class EntityConfigurationHeader(BaseModel):
    alg: str
    kid: str
    typ: Literal["entity-statement+jwt"]

    @field_validator("alg")
    @classmethod
    def check_alg(cls, alg, info: FieldValidationInfo):
        return _check_alg(alg, info)


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
