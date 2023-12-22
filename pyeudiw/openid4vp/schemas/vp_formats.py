from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class Algorithms(Enum):
    es256 = "ES256"
    es384 = "ES384"
    es512 = "ES512"
    rs256 = "RS256"
    rs384 = "RS384"
    rs512 = "RS512"


class VcSdJwt(BaseModel):
    sd_jwt_alg_values: List[Algorithms] = Field([], alias='sd-jwt_alg_values')
    kb_jwt_alg_values: List[Algorithms] = Field([], alias='kb-jwt_alg_values')


class VpFormats(BaseModel):
    vc_sd_jwt: VcSdJwt = Field(..., alias='vc+sd-jwt')
