import json
from typing import Literal, TypeAlias

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.okp import OKPKey
from cryptojwt.jwk.rsa import RSAKey

from pyeudiw.jwk import JWK
from pyeudiw.jwk.parse import parse_x5c_keys
from pyeudiw.jwt.log import logger
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.tools.utils import iat_now

from .exceptions import LifetimeException

KeyLike: TypeAlias = ECKey | RSAKey | OKPKey | SYMKey
SerializationFormat = Literal["compact", "json"]


class JWHelperInterface:
    def __init__(self, jwks: list[KeyLike | dict] | KeyLike | dict) -> None:
        """
        Creates an instance of JWEHelper.

        :raises TypeError: If the input jwks is not a list, dict, or a key-like object.

        :param jwks: The list of JWK used to crypt and encrypt the content of JWE.
        """
        self.jwks: list[KeyLike] = []
        if isinstance(jwks, dict):
            single_jwk = key_from_jwk_dict(jwks)
            self.jwks = [single_jwk]
        elif isinstance(jwks, list):
            self.jwks = []
            for j in jwks:
                if isinstance(j, dict):
                    j = key_from_jwk_dict(j)
                self.jwks.append(j)
        elif isinstance(jwks, (ECKey, RSAKey, OKPKey, SYMKey)):
            self.jwks = [jwks]
        else:
            raise TypeError(f"unable to handle input jwks with type {type(jwks)}")

    def get_jwk_by_kid(self, kid: str) -> KeyLike | None:
        """
        Returns the JWK with the given kid from the list of JWKs.

        :param kid: The key ID of the JWK to retrieve.
        :type kid: str
        :returns: The JWK with the given kid, or None if not found.
        :rtype: KeyLike | None
        """
        if not kid:
            return None
        for i in self.jwks:
            if i.kid == kid:
                return i
        return None


def serialize_payload(payload: dict | str | int | None) -> bytes | str | int:
    if isinstance(payload, dict):
        return json.dumps(payload)
    if isinstance(payload, (str, int)):
        return payload
    return ""


def find_self_contained_key(header: dict) -> tuple[set[str], JWK] | None:
    """Function find_self_contained_key evaluates a token header and attempts
    at finding a self contained key (a self contained contained header is a
    header that contains the full public material of the verifying key that
    should be used to verify a token).

    Currently recognized self contained headers are x5c, jwk, jku, x5u, x5t
    and trust_chain.
    It is responsability of the called to decide wether a self contained
    key representation is to be trusted.

    The functions returns the key and the set of claim used to infer the
    self contained key. In no self contained key can be found, None is
    returned instead.
    """
    if "x5c" in header:
        candidate_key: JWK | None = None
        try:
            candidate_key = parse_x5c_keys(header["x5c"])[0]
            return set(["5xc"]), candidate_key
        except Exception as e:
            logger.debug(
                f"failed to parse key from x5c chain {header['x5c']}", exc_info=e
            )
    if "jwk" in header:
        candidate_key = JWK(header["jwk"])
        return set(["jwk"]), candidate_key
    unsupported_claims = set(("trust_chain", "jku", "x5u", "x5t"))
    if unsupported_claims.intersection(header):
        raise NotImplementedError(
            f"self contained key extraction form header with claims {unsupported_claims} not supported yet"
        )
    return None


def is_payload_expired(token_payload: dict) -> bool:
    """
    Check if a JWT payload is expired.

    :param token_payload: The decoded JWT payload.
    :type token_payload: dict

    :returns: True if the payload is expired, False otherwise.
    :rtype: bool
    """
    exp = token_payload.get("exp", None)
    if not exp:
        return True
    if exp < iat_now():
        return True
    return False


def is_jwt_expired(token: str) -> bool:
    """
    Check if a JWT token is expired.

    :param token: The JWT token.
    :type token: str

    :returns: True if the token is expired, False otherwise.
    :rtype: bool
    """
    payload = decode_jwt_payload(token)
    return is_payload_expired(payload)


def validate_jwt_timestamps_claims(payload: dict, tolerance_s: int = 0) -> None:
    """
    Validates the 'iat', 'exp', and 'nbf' claims in a JWT payload, comparing
    them with the current time.
    The function assumes that the time in the payload claims is expressed as
    seconds since the epoch, as required by rfc 7519.
    To account for a clock skew between the token issuer and the token
    verifier, the optional argument tolerance_s can be used. As suggested by
    rfc 7519, it is recommended to keep the tolerance window to no more than
    a few minutes.

    :param payload: The decoded JWT payload.
    :type payload: dict
    :param tolerance_s: optional tolerance window, in seconds, which can be \
        used to account for some clock skew between the token issuer and the \
        token verifier.
    :type tolerance_s: int

    :raises LifetimeException: If any of the claims are invalid.
    """
    current_time = iat_now()

    if "iat" in payload:
        if payload["iat"] - tolerance_s > current_time:
            raise LifetimeException("Future issue time, token is invalid.")

    if "exp" in payload:
        if payload["exp"] + tolerance_s <= current_time:
            raise LifetimeException("Token has expired.")

    if "nbf" in payload:
        if payload["nbf"] - tolerance_s > current_time:
            raise LifetimeException("Token not yet valid.")
