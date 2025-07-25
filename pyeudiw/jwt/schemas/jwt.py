from typing import Optional

from pydantic import BaseModel, Field

from pyeudiw.federation.schemas.openid_credential_verifier import (
    EncryptionAlgValuesSupported,
    EncryptionEncValuesSupported,
    SigningAlgValuesSupported,
)


class JWTConfig(BaseModel):
    default_sig_alg: SigningAlgValuesSupported
    default_enc_alg: EncryptionAlgValuesSupported
    default_enc_enc: EncryptionEncValuesSupported
    default_exp: int = Field(..., gt=0)  # default_exp must be greater than 0
    access_token_exp: Optional[int] = Field(None, gt=0)  # access_token_exp must be greater than 0
    refresh_token_exp: Optional[int] = Field(None, gt=0) # refresh_token_exp must be greater than 0
    par_exp: Optional[int] = Field(None, gt=0) # par_exp must be greater than 0
    enc_alg_supported: list[EncryptionAlgValuesSupported]
    enc_enc_supported: list[EncryptionEncValuesSupported]
    sig_alg_supported: list[SigningAlgValuesSupported]
