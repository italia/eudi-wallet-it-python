import hashlib
import uuid

from pydantic import BaseModel, HttpUrl
from pyeudiw.jwk.schema import JwkSchema
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.tools.utils import iat_now
from typing import Literal


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
    jwk: JwkSchema


class DPoPTokenPayloadSchema(BaseModel):
    # body
    jti: str
    htm: Literal["GET", "POST", "get", "post"]
    htu: HttpUrl
    iat: int
    ath: str


class DPoPIssuer:
    def __init__(self, htu :str, token: str, private_jwk: dict):
        self.token = token
        self.private_jwk = private_jwk
        self.signer = JWSHelper(private_jwk)
        self.htu = htu

    @property
    def proof(self):
        data = {
            "jti": str(uuid.uuid4()),
            "htm": "GET",
            "htu": self.htu,
            "iat": iat_now(),
            "ath": hashlib.sha256(self.token.encode()).hexdigest()
        }
        jwt = self.signer.sign(data)
        return jwt
        # TODO assertion

class DPoPVerifier:
    dpop_header_prefix = 'DPoP '
    
    def __init__(
        self,
        public_jwk: dict,
        http_header_authz :str,
        http_header_dpop :str,
    ):
        self.public_jwk = public_jwk
        self.dpop_token = (
            http_header_authz.replace(self.dpop_header_prefix, '') 
            if self.dpop_header_prefix in http_header_authz 
            else http_header_authz
        )
        self.proof = http_header_dpop
    
    @property
    def is_valid(self):
        jws_verifier = JWSHelper(self.public_jwk)
        dpop_valid = jws_verifier.verify(self.dpop_token)
        payload = unpad_jwt_payload(self.proof)
        proof_valid = hashlib.sha256(self.dpop_token.encode()).hexdigest() == payload['ath']
        return dpop_valid and proof_valid 
