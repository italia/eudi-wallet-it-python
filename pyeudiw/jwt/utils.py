import base64
import json
import re
from typing import Dict

from pyeudiw.jwk import find_jwk_by_kid
from pyeudiw.jwt.exceptions import JWTInvalidElementPosition, JWTDecodeError

# jwt regexp pattern is non terminating, hence it match jwt, sd-jwt and sd-jwt with kb
JWT_REGEXP = r'^[_\w\-]+\.[_\w\-]+\.[_\w\-]+'


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
    if position < 0:
        raise JWTInvalidElementPosition(
            f"Cannot accept negative position {position}")
    
    if position > 2:
        raise JWTInvalidElementPosition(
            f"Cannot accept position greater than 2 {position}")

    splitted_jwt = jwt.split(".")

    if (len(splitted_jwt) - 1) < position:
        raise JWTInvalidElementPosition(
            f"JWT has no element in position {position}")

    try:
        if isinstance(jwt, bytes):
            jwt = jwt.decode()

        b64_data = jwt.split(".")[position]
        data = json.loads(base64_urldecode(b64_data))
        return data
    except Exception as e:
        raise JWTDecodeError(f"Unable to decode JWT element: {e}")


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

    if header.get("enc", None) is None:
        return False

    return True


def base64_urlencode(v: bytes) -> str:
    """Urlsafe base64 encoding without padding symbols

    :returns: the encooded data
    :rtype: str
    """
    return base64.urlsafe_b64encode(v).decode("ascii").strip("=")


def base64_urldecode(v: str) -> bytes:
    """Urlsafe base64 decoding. This function will handle missing
    padding symbols.

    :returns: the decoded data in bytes, format, convert to str use method '.decode("utf-8")' on result
    :rtype: bytes
    """
    padded = f"{v}{'=' * divmod(len(v), 4)[1]}"
    return base64.urlsafe_b64decode(padded)
