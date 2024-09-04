import re
from typing import Dict, Literal

from pydantic import BaseModel, HttpUrl

from pyeudiw.jwk.schemas.public import JwkSchema

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


class SDJWTSchema(BaseModel):
    iss: HttpUrl
    iat: int
    exp: int
    sub: str
    _sd_alg: str
    cnf: Dict[Literal["jwk"], JwkSchema]
