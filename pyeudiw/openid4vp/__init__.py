from typing import Tuple

from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt import verify_sd_jwt
from pyeudiw.jwt.utils import unpad_jwt_payload


def check_vp_token(vp_token: str, config: dict, sd_specification: dict, sd_jwt: dict) -> Tuple[str | None, dict]:
    payload = unpad_jwt_payload(vp_token)
    holder_jwk = JWK(payload["cnf"]["jwk"])
    issuer_jwk = JWK(config["federation"]["federation_jwks"][1])

    result, binding = verify_sd_jwt(
        vp_token, sd_specification, sd_jwt, issuer_jwk, holder_jwk)
    nonce = binding.get("nonce", None)
    claims = result["holder_disclosed_claims"]

    try:
        return True, {"nonce": nonce, "claims": claims}
    except Exception as e:
        return False, str(e)
