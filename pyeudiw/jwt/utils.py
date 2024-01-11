import base64
import json
import re

from typing import Dict
from pyeudiw.jwt.exceptions import JWTInvalidElementPosition
from pyeudiw.jwk import find_jwk

# JWT_REGEXP = r"^(([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*\.([-A-Za-z0-9\=_])*)$"
JWT_REGEXP = r'^[\w\-]+\.[\w\-]+\.[\w\-]+'


def decode_jwt_element(jwt: str, position: int) -> dict:
    """
    Decodes the element in a determinated position.

    :param jwt: a string that represents the jwt.
    :type jwt: str
    :param position: the position of segment to unpad.
    :type position: int

    :raises JWTInvalidElementPosition: If the JWT element position is greather then one or less of 0

    :returns: a dict with the content of the decoded section.
    :rtype: dict
    """
    if position > 1 or position < 0:
        raise JWTInvalidElementPosition(f"JWT has no element in position {position}")

    if isinstance(jwt, bytes):
        jwt = jwt.decode()
    
    b = jwt.split(".")[position]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data


def decode_jwt_header(jwt: str) -> dict:
    """
    Decodes the jwt header.

    :param jwt: a string that represents the jwt.
    :type jwt: str

    :returns: a dict with the content of the decoded header.
    :rtype: dict
    """
    return decode_jwt_element(jwt, position=0)


def decode_jwt_payload(jwt: str) -> dict:
    """
    Decodes the jwt payload.

    :param jwt: a string that represents the jwt.
    :type jwt: str

    :returns: a dict with the content of the decoded payload.
    :rtype: dict
    """
    return decode_jwt_element(jwt, position=1)


def get_jwk_from_jwt(jwt: str, provider_jwks: Dict[str, dict]) -> dict:
    """
    Find the JWK inside the provider JWKs with the kid 
    specified in jwt header.

    :param jwt: a string that represents the jwt.
    :type jwt: str
    :param provider_jwks: a dictionary that contains one or more JWKs with the KID as the key.
    :type provider_jwks: Dict[str, dict]

    :raises InvalidKid: if kid is None.
    :raises KidNotFoundError: if kid is not in jwks list.

    :returns: the jwk as dict.
    :rtype: dict
    """
    head = decode_jwt_header(jwt)
    kid = head["kid"]
    if isinstance(provider_jwks, dict) and provider_jwks.get('keys'):
        provider_jwks = provider_jwks['keys']
    
    return find_jwk(kid, provider_jwks)


def is_jwt_format(jwt: str) -> bool:
    """
    Check if a string is in JWT format.
    
    :param jwt: a string that represents the jwt.
    :type jwt: str

    :returns: True if the string is a JWT, False otherwise.
    :rtype: bool
    """

    res = re.match(JWT_REGEXP, jwt)
    return bool(res)

def is_jwe_format(jwt: str):
    """
    Check if a string is in JWE format.
    
    :param jwt: a string that represents the jwt.
    :type jwt: str

    :returns: True if the string is a JWE, False otherwise.
    :rtype: bool
    """

    if not is_jwt_format(jwt):
        return False
    
    header = decode_jwt_header(jwt)

    if header.get("enc", None) == None:
        return False
    
    return True

def is_jws_format(jwt: str):
    """
    Check if a string is in JWS format.
    
    :param jwt: a string that represents the jwt.
    :type jwt: str

    :returns: True if the string is a JWS, False otherwise.
    :rtype: bool
    """
    if not is_jwt_format(jwt):
        return False
    
    return not is_jwe_format(jwt)