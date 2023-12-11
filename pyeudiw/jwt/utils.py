import base64
import json
import re

from typing import Dict
from pyeudiw.jwt.exceptions import JWTInvalidElementPosition
from pyeudiw.jwk import find_jwk

# JWT_REGEXP = r"^(([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*)$"
JWT_REGEXP = r'^[\w\-]+\.[\w\-]+\.[\w\-]+'


def decode_jwt_element(jwt: str, position: int) -> dict:
    if position > 1 or position < 0:
        raise JWTInvalidElementPosition(f"JWT has no element in position {position}")

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
    
    return find_jwk(kid, provider_jwks)


def is_jwt_format(jwt: str) -> bool:
    res = re.match(JWT_REGEXP, jwt)
    return bool(res)
