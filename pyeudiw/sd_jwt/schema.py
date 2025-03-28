import logging
import re
import sys
from typing import Dict, Literal, Optional, TypeVar

from typing_extensions import Self

if float(f"{sys.version_info.major}.{sys.version_info.minor}") >= 3.12:
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from pydantic import BaseModel, HttpUrl, field_validator, model_validator

from pyeudiw.jwk.schemas.public import JwkSchema

_OptionalDict_T = TypeVar("T", None, dict)

_IDENTIFYING_VC_TYP = "dc+sd-jwt"
_IDENTIFYING_KB_TYP = "kb+jwt"

# this pattern matches sd-jwt and sd-jwt w/ kb
SD_JWT_REGEXP = r"^([-A-Za-z0-9_]+\.[-A-Za-z0-9_]+\.[-A-Za-z0-9_]+)(~[-A-Za-z0-9_]+)*(~)([-A-Za-z0-9_]+\.[-A-Za-z0-9_]+\.[-A-Za-z0-9_]+)*$"
# this pattern matches sd-jwt w/ kb
SD_JWT_KB_REGEXP = r"^([-A-Za-z0-9_]+\.[-A-Za-z0-9_]+\.[-A-Za-z0-9_]+)(~[-A-Za-z0-9_]+)*(~)([-A-Za-z0-9_]+\.[-A-Za-z0-9_]+\.[-A-Za-z0-9_]+)$"


def is_sd_jwt_format(sd_jwt: str) -> bool:
    res = re.match(SD_JWT_REGEXP, sd_jwt)
    return bool(res)


def is_sd_jwt_kb_format(sd_jwt_kb: str) -> bool:
    res = re.match(SD_JWT_KB_REGEXP, sd_jwt_kb)
    return bool(res)


logger = logging.getLogger(__name__)


class VcSdJwtHeaderSchema(BaseModel):
    typ: str
    alg: str
    kid: Optional[str] = None
    trust_chain: Optional[list[str]] = None
    x5c: Optional[str] = None
    vctm: Optional[list[str]] = None

    @field_validator("typ")
    def validate_typ(cls, v: str) -> str:
        if v != _IDENTIFYING_VC_TYP:
            raise ValueError(
                f"header parameter [typ] must be '{_IDENTIFYING_VC_TYP}', found instead '{v}'"
            )
        return v

    @model_validator(mode="after")
    def check_typ_when_not_x5c(self) -> Self:
        if (not self.x5c) and (not self.kid):
            raise ValueError("[kid] must be defined if [x5c] claim is not defined")
        return self


class _StatusAssertionSchema(BaseModel):
    credential_hash_alg: str


class _StatusSchema(BaseModel):
    status_assertion: _StatusAssertionSchema


class _EvidenceSchema(BaseModel):
    method: str | list | dict


class _VerificationSchema(BaseModel):
    trust_framework: str
    assurance_level: str
    evidence: _EvidenceSchema


class VcSdJwtPayloadSchema(BaseModel):
    iss: HttpUrl
    sub: str
    iat: int  # selectively disclosable
    exp: int
    status: dict
    cnf: Dict[Literal["jwk"], JwkSchema]
    vct: str
    verification: dict
    _sd_alg: str

    _sd: Optional[list[str]] = None

    @field_validator("status")
    def validate_status(cls, v: dict) -> dict:
        try:
            _StatusSchema(**v)
        except ValueError as e:
            raise ValueError(
                f"parameter [status] value '{v}' does not comply with schema {_StatusSchema.model_fields}: {e}"
            )
        return v

    @field_validator("verification")
    def validate_verification(cls, v: dict) -> dict:
        try:
            _VerificationSchema(**v)
        except ValueError as e:
            raise ValueError(
                f"parameter [verification] value '{v}' does not comply with schema {_VerificationSchema.model_fields}: {e}"
            )
        return v


class KeyBindingJwtHeader(BaseModel):
    typ: str
    alg: str

    @field_validator("typ")
    def validate_typ(cls, v: str) -> str:
        if v != _IDENTIFYING_KB_TYP:
            raise ValueError(
                f"header parameter [typ] must be '{_IDENTIFYING_KB_TYP}', found instead '{v}'"
            )
        return v


class KeyBindingJwtPayload(BaseModel):
    iat: int
    aud: str
    nonce: str
    sd_hash: str


class VerifierChallenge(TypedDict):
    aud: str
    nonce: str
