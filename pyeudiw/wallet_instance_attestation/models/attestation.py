from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, HttpUrl, field_validator
from pydantic_core.core_schema import ValidationInfo

from pyeudiw.tools.schema_utils import check_algorithm
from pyeudiw.wallet_instance_attestation.models.cnf import CNFSchema

_default_supported_algorithms = [
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


class VPFormatSchema(BaseModel):
    jwt_vp_json: Dict[Literal["alg_values_supported"], List[str]]
    jwt_vc_json: Dict[Literal["alg_values_supported"], List[str]]


class WalletInstanceAttestationHeader(BaseModel):
    alg: str
    typ: Literal["oauth-client-attestation+jwt"]
    kid: str #id pub-key wallet provider
    trust_chain: Optional[List[str]] = None
    x5c: List[str] = None


    @field_validator("alg")
    @classmethod
    def _check_alg(cls, alg, info: ValidationInfo):
        check_algorithm(alg, info)
        return alg


class WalletInstanceAttestationPayload(BaseModel):
    iss: HttpUrl
    sub: str
    exp: int
    cnf: CNFSchema

    iat: Optional[int] = None
    nbf: Optional[int] = None
    wallet_link: Optional[HttpUrl] = None
    wallet_name: Optional[str] = None
    status: Optional[str] = None
