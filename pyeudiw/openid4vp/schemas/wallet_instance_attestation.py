from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, HttpUrl, field_validator
from pydantic_core.core_schema import FieldValidationInfo

from pyeudiw.openid4vp.schemas.cnf_schema import CNFSchema
from pyeudiw.tools.schema_utils import check_algorithm

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
    typ: Literal["wallet-attestation+jwt"]
    kid: str
    x5c: Optional[List[str]] = None
    trust_chain: Optional[List[str]] = None

    @field_validator("alg")
    @classmethod
    def _check_alg(cls, alg, info: FieldValidationInfo):
        return check_algorithm(alg, info)


class WalletInstanceAttestationPayload(BaseModel):
    iss: HttpUrl
    sub: str
    iat: int
    exp: int
    type: Literal["WalletInstanceAttestation"]
    policy_uri: HttpUrl
    tos_uri: HttpUrl
    logo_uri: HttpUrl
    attested_security_context: HttpUrl
    cnf: CNFSchema
    authorization_endpoint: str
    response_types_supported: List[str]
    vp_formats_supported: VPFormatSchema
    request_object_signing_alg_values_supported: List[str]
    presentation_definition_uri_supported: bool
