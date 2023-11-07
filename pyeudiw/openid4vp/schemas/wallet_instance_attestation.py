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
    aal: HttpUrl
    cnf: CNFSchema
    # Wallet Capabilities
    type: Optional[Literal["WalletInstanceAttestation"]]
    policy_uri: Optional[HttpUrl]
    tos_uri: Optional[HttpUrl]
    logo_uri: Optional[HttpUrl]
    authorization_endpoint: Optional[str]
    response_types_supported: Optional[List[str]]
    vp_formats_supported: Optional[VPFormatSchema]
    request_object_signing_alg_values_supported: Optional[List[str]]
    presentation_definition_uri_supported: Optional[bool]
