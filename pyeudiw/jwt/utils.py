import base64
import json
import re

from pyeudiw.jwt.exceptions import JWTInvalidElementPosition

# JWT_REGEXP = r"^(([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*)$"
JWT_REGEXP = r'^[\w\-]+\.[\w\-]+\.[\w\-]+'


def decode_jwt_element(jwt: str, position: int) -> dict:
    if position > 1:
        raise JWTInvalidElementPosition(f"JWT has no jwt element in position {position}")

    if isinstance(jwt, bytes):
        jwt = jwt.decode()
    b = jwt.split(".")[position]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data


def decode_jwt_header(jwt: str) -> dict:
    return decode_jwt_element(jwt, position=0)


def decode_jwt_payload(jwt: str) -> dict:
    return decode_jwt_element(jwt, position=1)


def get_jwk_from_jwt(jwt: str, provider_jwks: dict) -> dict:
    """
        docs here
    """
    head = decode_jwt_header(jwt)
    kid = head["kid"]
    if isinstance(provider_jwks, dict) and provider_jwks.get('keys'):
        provider_jwks = provider_jwks['keys']
    for jwk in provider_jwks:
        if jwk["kid"] == kid:
            return jwk
    return {}


def is_jwt_format(jwt: str) -> bool:
    res = re.match(JWT_REGEXP, jwt)
    return bool(res)
