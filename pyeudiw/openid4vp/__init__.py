from typing import Tuple

from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header
from pyeudiw.sd_jwt import verify_sd_jwt
from pyeudiw.openid4vp.exceptions import KIDNotFound
from pyeudiw.openid4vp.schemas.vp_token import VPTokenPayload, VPTokenHeader


def check_vp_token(vp_token: str, sd_specification: dict, jwks: list[dict], config: dict = {"no_randomness": True}) -> Tuple[str | None, dict]:
    payload = unpad_jwt_payload(vp_token)
    VPTokenPayload(**payload)

    headers = unpad_jwt_header(vp_token)
    VPTokenHeader(**headers)

    kid = headers["kid"]

    vp = unpad_jwt_payload(payload["vp"])

    issuer_jwk = jwks.get(kid, None)

    if not issuer_jwk:
        raise KIDNotFound(f"kid {kid} not present")

    issuer_jwk = JWK(issuer_jwk)
    holder_jwk = JWK(vp["cnf"]["jwk"])

    result = verify_sd_jwt(
        payload["vp"], sd_specification, config, issuer_jwk, holder_jwk)

    nonce = payload.get("nonce", None)
    claims = result["holder_disclosed_claims"]

    try:
        return True, {"nonce": nonce, "claims": claims}
    except Exception as e:
        return False, str(e)
