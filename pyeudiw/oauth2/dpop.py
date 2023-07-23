from pydantic import BaseModel, HttpUrl, validator

from pyeudiw.jwk import JWK
from pyeudiw.tools.jwt import JWSHelper

from typing import List, Literal, Optional


class DPoPTokenHeaderSchema(BaseModel):
    # header
    typ: Literal["dpop+jwt"]
    alg: Literal[
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
    ]
    jwk: SINGLE_REQUIRED_JSON

class DPoPTokenPayloadSchema(BaseModel):
    # body
    jti: str,
    htm: Literal["GET", "POST", "get", "post"],
    htu: HttpUrl
    iat: int
    ath: str


class DPoPIssuer:
    def __init__(self, token :str, private_jwk :dict):
        self.token = token
        self.private_jwk = private_jwk
    
    def get_proof(self):
        pass


class DPoPVerifier:
    def __init__(
        self, token :str, 
        public_jwk :dict, 
        http_header_authz :str, 
        http_header_dpop :str
    ):
        self.token = token
        self.public_jwk = private_jwk
    
    def validate_proof(self):
        pass
