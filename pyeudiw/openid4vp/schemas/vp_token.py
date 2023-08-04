from typing import Literal

from pydantic import BaseModel, HttpUrl, field_validator
from pydantic_core.core_schema import FieldValidationInfo

from pyeudiw.sd_jwt.schema import is_sd_jwt_format
from pyeudiw.tools.schema_utils import check_algorithm


class VPTokenHeader(BaseModel):
    alg: str
    kid: str
    typ: Literal["JWT"]

    @field_validator("alg")
    @classmethod
    def _check_alg(cls, alg, info: FieldValidationInfo):
        return check_algorithm(alg, info)


class VPTokenPayload(BaseModel):
    iss: HttpUrl
    jti: str
    aud: HttpUrl
    iat: int
    exp: int
    nonce: str
    vp: str

    @field_validator("vp")
    @classmethod
    def _check_vp(cls, vp):
        if is_sd_jwt_format(vp):
            return vp
        else:
            raise ValueError("vp is not in a SDJWT format.")
