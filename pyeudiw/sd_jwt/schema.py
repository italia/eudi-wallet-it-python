import re
from typing import Dict, Literal

from pydantic import BaseModel, HttpUrl

from pyeudiw.jwk.schema import JwkSchema

SD_JWT_REGEXP = r"^(([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*)(~([-A-Za-z0-9\=_\.])*)*$"


def is_sd_jwt_format(sd_jwt: str) -> bool:
    res = re.match(SD_JWT_REGEXP, sd_jwt)
    return bool(res)


def is_sd_jwt_list_format(sd_jwt_list: list[str]) -> bool:
    if len(sd_jwt_list) == 0:
        return False

    for sd_jwt in sd_jwt_list:
        if not is_sd_jwt_format(sd_jwt):
            return False

    return True


class SDJWTSchema(BaseModel):
    iss: HttpUrl
    iat: int
    exp: int
    sub: str
    _sd_alg: str
    cnf: Dict[Literal["jwk"], JwkSchema]
