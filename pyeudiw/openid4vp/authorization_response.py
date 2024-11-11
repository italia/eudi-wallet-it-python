from dataclasses import dataclass
import json

from pyeudiw.jwt import JWEHelper, JWSHelper
from pyeudiw.jwk.exceptions import KidNotFoundError
from pyeudiw.jwt.utils import decode_jwt_header, is_jwe_format, is_jwt_format

_RESPONSE_KEY = "response"


@dataclass
class AuthorizeResponsePayload:
    state: str
    vp_token: str | list[str]
    presentation_submission: dict

    def serialize_json(self) -> str:
        return json.dumps(self.__dict__)


def _get_jwk_kid_from_store(jwt: str, key_store: dict[str, dict]) -> dict:
    headers = decode_jwt_header(jwt)
    kid: str | None = headers.get("kid", None)
    if kid is None:
        raise KidNotFoundError("authorization response is missing mandatory parameter [kid] in header section")
    jwk_dict = key_store.get(kid, None)
    if jwk_dict is None:
        raise KidNotFoundError(f"authorization response is encrypted with jwk with kid='{kid}' not found in store")
    return jwk_dict


def _decrypt_jwe(jwe: str, decrypting_jwk: dict[str, any]) -> dict:
    decrypter = JWEHelper(decrypting_jwk)
    return decrypter.decrypt(jwe)


def _verify_and_decode_jwt(jwt: str, verifying_jwk: dict[str, any]) -> dict:
    verifier = JWSHelper(verifying_jwk)
    raw_payload: str = verifier.verify(jwt)["msg"]
    payload: dict = json.loads(raw_payload)
    return payload


@dataclass
class AuthorizeResponseDirectPost:
    response: str  # jwt

    def __post_init__(self):
        jwt = self.response
        if not is_jwe_format(jwt) and not is_jwt_format(jwt):
            raise ValueError(f"input {_RESPONSE_KEY}={jwt} is neither jwt not jwe format")

    def decode_payload(self, key_store_by_kid: dict[str, dict]) -> AuthorizeResponsePayload:
        jwt = self.response
        jwk_dict = _get_jwk_kid_from_store(jwt, key_store_by_kid)

        payload = {}
        if is_jwe_format(jwt):
            payload = _decrypt_jwe(jwt, jwk_dict)
        elif is_jwt_format(jwt):
            payload = _verify_and_decode_jwt(jwt, jwk_dict)
        else:
            raise ValueError(f"unexpected state: input jwt={jwt} is neither a jwt nor a jwe")
        return AuthorizeResponsePayload(**payload)
