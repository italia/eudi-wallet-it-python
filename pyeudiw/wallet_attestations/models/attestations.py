from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator
from pydantic_core.core_schema import ValidationInfo

from pyeudiw.jwk.schemas.public import JwkSchema
from pyeudiw.tools.schema_utils import check_algorithm
from pyeudiw.wallet_attestations.models.cnf import CNFSchema

_user_authentications = Literal[
    "iso_18045_high", "iso_18045_moderate", "iso_18045_basic"
]
_key_storage = Literal["iso_18045_high", "iso_18045_moderate", "iso_18045_basic"]


class VPFormatSchema(BaseModel):
    jwt_vp_json: Dict[Literal["alg_values_supported"], List[str]]
    jwt_vc_json: Dict[Literal["alg_values_supported"], List[str]]


class WalletInstanceAttestationHeader(BaseModel):
    alg: str
    typ: Literal["oauth-client-attestation+jwt"]
    kid: str  # id pub-key wallet provider
    # x5c REQUIRED per EUDI TS3 (Wallet Unit Attestation): PID/Attestation Providers SHALL verify
    # the WIA signature under the public key in the signing cert in x5c and against the Trusted
    # List for Wallet Providers. See ts3-wallet-unit-attestation Section 2.2.1.2.
    x5c: List[str]
    trust_chain: Optional[List[str]] = None

    @field_validator("alg")
    @classmethod
    def _check_alg(cls, alg, info: ValidationInfo):
        check_algorithm(alg, info)
        return alg

    # todo add claims validators


class WalletInstanceAttestationPayload(BaseModel):
    iss: HttpUrl
    sub: str
    exp: int
    cnf: CNFSchema

    iat: Optional[int] = None
    nbf: Optional[int] = None
    wallet_link: Optional[HttpUrl] = None
    wallet_name: Optional[str] = None
    status: Optional[dict[str, dict]] = None


class WalletUnitAttestationHeader(BaseModel):
    alg: str
    typ: Literal["key-attestation+jwt"]
    kid: str  # id pub-key wallet provider
    x5c: List[str]
    trust_chain: Optional[List[str]] = None

    @field_validator("alg")
    @classmethod
    def _check_alg(cls, alg, info: ValidationInfo):
        check_algorithm(alg, info)
        return alg


class WalletUnitAttestationPayload(BaseModel):
    iss: HttpUrl
    exp: int
    iat: int
    attested_keys: list[JwkSchema]
    key_storage: list[_key_storage] = Field(..., min_length=1)
    user_authentication: list[_user_authentications] = Field(..., min_length=1)
    status: dict[str, dict] = None
    certification: Optional[HttpUrl] = None
