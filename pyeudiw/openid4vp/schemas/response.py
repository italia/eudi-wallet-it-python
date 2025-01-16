from dataclasses import dataclass
from enum import Enum

from pyeudiw.jwt.utils import is_jwe_format, is_jwt_format


class ResponseMode(str, Enum):
    direct_post = "direct_post"
    direct_post_jwt = "direct_post.jwt"


@dataclass
class AuthorizeResponseDirectPostJwt:
    response: str  # jwt

    def __post_init__(self):
        jwt = self.response
        if not is_jwe_format(jwt) and not is_jwt_format(jwt):
            raise ValueError(f"input response={jwt} is neither jwt not jwe format")

    # def decode_payload(self, key_store_by_kid: dict[str, dict]) -> AuthorizeResponsePayload:
    #     jwt = self.response
    #     jwk_dict = _get_jwk_kid_from_store(jwt, key_store_by_kid)

    #     payload = {}
    #     if is_jwe_format(jwt):
    #         payload = _decrypt_jwe(jwt, jwk_dict)
    #     elif is_jwt_format(jwt):
    #         payload = _verify_and_decode_jwt(jwt, jwk_dict)
    #     else:
    #         raise ValueError(f"unexpected state: input jwt={jwt} is neither a jwt nor a jwe")
    #     return AuthorizeResponsePayload(**payload)


@dataclass
class AuthorizeResponsePayload:
    """
    AuthorizeResponsePayload is a simple schema class for
        https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-parameters
    only for the case when presentation submission is used over DCQL.
    """
    state: str
    vp_token: str | list[str]
    presentation_submission: dict
