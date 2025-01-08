import json
from pyeudiw.jwk import JWK
from pyeudiw.jwk.parse import parse_key_from_x5c

from pyeudiw.jwt.log import logger


from typing import TypeAlias, Literal

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.okp import OKPKey
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.jwk import key_from_jwk_dict

KeyLike: TypeAlias = ECKey | RSAKey | OKPKey | SYMKey
SerializationFormat = Literal["compact", "json"]

class JWHelperInterface:
    def __init__(self, jwks: list[KeyLike | dict] | KeyLike | dict):
        """
        Creates an instance of JWEHelper.

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
            candidate_key = parse_key_from_x5c(header["x5c"])
        except Exception as e:
            logger.debug(f"failed to parse key from x5c chain {header['x5c']}", exc_info=e)
        return set(["5xc"]), candidate_key
    if "jwk" in header:
        candidate_key = JWK(header["jwk"])
        return set(["jwk"]), candidate_key
    unsupported_claims = set(("trust_chain", "jku", "x5u", "x5t"))
    if unsupported_claims.intersection(header):
        raise NotImplementedError(f"self contained key extraction form header with claims {unsupported_claims} not supported yet")
    return None
