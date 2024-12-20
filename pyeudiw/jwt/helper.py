import json
from pyeudiw.jwk import JWK
from pyeudiw.jwk.parse import parse_key_from_x5c

from pyeudiw.jwt.log import logger


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
