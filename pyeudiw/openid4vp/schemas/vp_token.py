from typing import Literal

from pydantic import BaseModel, field_validator, HttpUrl
from pydantic_core.core_schema import FieldValidationInfo

from pyeudiw.tools.schema_utils import check_algorithm


class VPTokenHeader(BaseModel):
    alg = str
    kid = str
    typ = Literal["JWT"]

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

    # TODO: vp validation (SDJWT)