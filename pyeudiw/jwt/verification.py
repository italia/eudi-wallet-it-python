
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.tools.utils import iat_now

from cryptojwt.jwk import JWK


def verify_jws_with_key(jws: str, key: JWK) -> None:
    """
    :raises JWSVerificationError: is signature verification fails for *any* reason
    """
    try:
        verifier = JWSHelper(key)
        verifier.verify(jws)
    except Exception as e:
        raise JWSVerificationError(f"error during signature verification: {e}", e)


def is_payload_expired(token_payload: dict) -> bool:
    exp = token_payload.get("exp", None)
    if not exp:
        return True
    if exp < iat_now():
        return True
    return False


def is_jwt_expired(token: str) -> bool:
    payalod = decode_jwt_payload(token)
    return is_payload_expired(payalod)
