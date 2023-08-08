from typing import Tuple

from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.sd_jwt import verify_sd_jwt


def check_vp_token(vp_token: str, sd_specification: dict, issuer_jwk: JWK, config: dict = {"no_randomness": True}) -> Tuple[str | None, dict]:
    payload = unpad_jwt_payload(vp_token)

    vp = unpad_jwt_payload(payload["vp"])
    holder_jwk = JWK(vp["cnf"]["jwk"])
    
    result = verify_sd_jwt(
        payload["vp"], sd_specification, config, issuer_jwk, holder_jwk)
        
    nonce = payload.get("nonce", None)
    claims = result["holder_disclosed_claims"]

    try:
        return True, {"nonce": nonce, "claims": claims}
    except Exception as e:
        return False, str(e)
