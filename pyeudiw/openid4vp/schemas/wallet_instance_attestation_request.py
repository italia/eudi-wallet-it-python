from typing import Literal

from pydantic import BaseModel, HttpUrl, field_validator
from pydantic_core.core_schema import FieldValidationInfo

from pyeudiw.openid4vp.schemas.cnf_schema import CNFSchema
from pyeudiw.tools.schema_utils import check_algorithm


class WalletInstanceAttestationRequestHeader(BaseModel):
    alg: str
    typ: Literal["var+jwt"]
    kid: str

    @field_validator("alg")
    @classmethod
    def _check_alg(cls, alg, info: FieldValidationInfo):
        return check_algorithm(alg, info)


class WalletInstanceAttestationRequestPayload(BaseModel):
    iss: str
    aud: HttpUrl
    jti: str
    type: Literal["WalletInstanceAttestationRequest"]
    nonce: str
    cnf: CNFSchema
    # TODO: check if `iat` and `exp` are required. They are not listed in the table but are in the example.
    # https://github.com/italia/eudi-wallet-it-docs/blob/versione-corrente/docs/en/wallet-instance-attestation.rst#format-of-the-wallet-instance-attestation-request
    iat: int
    exp: int
