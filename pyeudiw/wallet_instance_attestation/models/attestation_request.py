from typing import Literal

from pydantic import BaseModel, HttpUrl, field_validator
from pydantic_core.core_schema import ValidationInfo

from pyeudiw.tools.schema_utils import check_algorithm
from pyeudiw.wallet_instance_attestation.models.cnf import CNFSchema


class WalletInstanceAttestationRequestHeader(BaseModel):
    alg: str
    typ: Literal["attestations-request+jwt"]
    kid: str

    @field_validator("alg")
    @classmethod
    def _check_alg(cls, alg, info: ValidationInfo):
        check_algorithm(alg, info)
        return alg


class WalletInstanceAttestationRequestPayload(BaseModel):
    iss: str
    aud: HttpUrl
    exp: int
    iat: int
    nonce: str

    hardware_signature: str
    integrity_assertion: str
    attested_key: str
    hardware_key_tag: str

    cnf: CNFSchema
