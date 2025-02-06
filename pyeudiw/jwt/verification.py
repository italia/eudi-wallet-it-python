from cryptojwt.jwk import JWK

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper


def verify_jws_with_key(jws: str, key: JWK) -> None:
    """
    :raises JWSVerificationError: is signature verification fails for *any* reason
    """
    try:
        verifier = JWSHelper(key)
        verifier.verify(jws)
    except Exception as e:
        raise JWSVerificationError(f"error during signature verification: {e}", e)
