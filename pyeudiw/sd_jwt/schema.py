import re
from typing import Any, Dict, Literal, Optional, TypeVar

from pydantic import BaseModel, HttpUrl, field_validator

from pyeudiw.jwk.schemas.public import JwkSchema


_OptionalDict_T = TypeVar('T', None, dict)

_IDENTIFYING_TYP = "vc+sd-jwt"

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


class VcSdJwtHeaderSchema(BaseModel):
    typ: str  # TODO: MUST be vc+sd-jwt
    alg: str
    kid: str
    trust_chain: Optional[list[str]] = None
    x5c: Optional[str] = None
    vctm: Optional[list[str]] = None

    @field_validator("typ")
    def validate_typ(cls, v: str) -> str:
        if v != _IDENTIFYING_TYP:
            raise ValueError(f"header parameter [typ] must be '{_IDENTIFYING_TYP}', found instead '{v}'")
        return v


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


class SDJWTPayloadSchema(BaseModel):
    iss: HttpUrl
    sub: str
    iat: int  # selectively disclosable
    exp: int
    status: dict
    cnf: Dict[Literal["jwk"], JwkSchema]
    vct: str
    verification: dict

    _sd_alg: str

    @field_validator("status")
    def validate_status(cls, v: dict) -> dict:
        try:
            _StatusSchema(**v)
        except ValueError as e:
            raise ValueError(f"parameter [status] value '{v}' does not comply with schema {_StatusSchema.model_fields}: {e}")
        return v

    @field_validator("verification")
    def validate_verification(cls, v: dict) -> dict:
        try:
            _VerificationSchema(**v)
        except ValueError as e:
            raise ValueError(f"parameter [verification] value '{v}' does not comply with schema {_VerificationSchema.model_fields}: {e}")
        return v


class PidVcSdJwtPayloadSchema(SDJWTPayloadSchema):
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    birth_date: Optional[Any] = None  # TODO: date is dd-mm-yyyy but I'm not sure if libraries parses them as str or a native format
    unique_id: Optional[str] = None
    tax_id_code: Optional[str] = None
