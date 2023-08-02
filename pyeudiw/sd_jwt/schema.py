import re

from pydantic import ValidationError

SD_JWT_REGEXP = r"^(([-A-Za-z0-9+\=])*\.([-A-Za-z0-9+\=])*\.([-A-Za-z0-9+\=])*)$"


def check_sd_jwt(sd_jwt: str) -> str:
    res = re.match(SD_JWT_REGEXP, sd_jwt)
    if not res:
        raise ValidationError(f"Vp_token is not a sd-jwt {sd_jwt}")

    return sd_jwt


def check_sd_jwt_list(sd_jwt_list: list[str]) -> list[str]:
    if len(sd_jwt_list) == 0:
        raise ValidationError("vp_token is empty")

    for sd_jwt in sd_jwt_list:
        check_sd_jwt(sd_jwt)

    return sd_jwt_list
