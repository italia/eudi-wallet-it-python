import json
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header

from pyeudiw.jwk.exceptions import KidNotFoundError

def _get_jwk_kid_from_store(jwt: str, key_store: dict[str, dict]) -> dict:
    headers = decode_jwt_header(jwt)
    kid: str | None = headers.get("kid", None)
    if kid is None:
        raise KidNotFoundError(
            "authorization response is missing mandatory parameter [kid] in header section"
        )
    jwk_dict = key_store.get(kid, None)
    if jwk_dict is None:
        raise KidNotFoundError(
            f"authorization response is encrypted with jwk with kid='{kid}' not found in store"
        )
    return jwk_dict


def _decrypt_jwe(jwe: str, decrypting_jwk: dict[str, any]) -> dict:
    decrypter = JWEHelper(decrypting_jwk)
    return decrypter.decrypt(jwe)


def _verify_and_decode_jwt(
    jwt: str, verifying_jwk: dict[dict, ECKey | RSAKey | dict]
) -> dict:
    verifier = JWSHelper(verifying_jwk)
    raw_payload: str = verifier.verify(jwt)["msg"]
    payload: dict = json.loads(raw_payload)
    return payload
