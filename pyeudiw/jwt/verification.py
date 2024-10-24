from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.tools.utils import iat_now

def verify_jws_with_key(jws: str, key: JWK) -> None:
    """
    :raises JWSVerificationError: is signature verification fails for *any* reason
    """
    try:
        verifier = JWSHelper(key)
        verifier.verify(jws)
    except Exception as e:
        raise JWSVerificationError(f"error during signature verification: {e}", e)

def is_jwt_expired(token: str) -> bool:
    """
    Check if a jwt is expired.
    
    :param token: a string that represents the jwt.
    :type token: str

    :returns: True if the token is expired, False otherwise.
    :rtype: bool
    """

    token_payload = decode_jwt_payload(token)

    exp = token_payload.get("exp", None)
    if not exp:
        return True
    elif exp < iat_now():
        return True
    return False
    

