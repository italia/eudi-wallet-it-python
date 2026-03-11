from dataclasses import dataclass
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator

from pyeudiw.jwt.utils import is_jwe_format, is_jwt_format


class ResponseMode(str, Enum):
    direct_post = "direct_post"
    direct_post_jwt = "direct_post.jwt"
    error = "error"


class ResponseSchema(BaseModel):
    state: Optional[str]
    nonce: str
    vp_token: str

    @field_validator("vp_token")
    @classmethod
    def _check_vp_token(cls, vp_token):
        if is_jwt_format(vp_token):
            return vp_token
        else:
            raise ValueError("vp_token is not in a JWT format.")


@dataclass
class AuthorizeResponseDirectPostJwt:
    response: str  # jwt

    def __post_init__(self):
        jwt = self.response
        if not is_jwe_format(jwt) and not is_jwt_format(jwt):
            raise ValueError(f"input response={jwt} is neither jwt not jwe format")


@dataclass
class AuthorizeResponsePayload:
    """
    AuthorizeResponsePayload is a simple schema class for https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-parameters
    for the DCQL (Duckle Query Language) flow.

    This class validates that the response contains the expected claims for DCQL.
    """

    state: str
    vp_token: str | list[str] | dict


@dataclass
class ErrorResponsePayload:
    state: str
    error: str
    error_description: str | None = None
