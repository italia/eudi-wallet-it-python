from typing import Optional

from pydantic import BaseModel, field_validator


class CredentialSpecificationConfig(BaseModel):
    """
    Configuration model for credential specification handling.
    """

    template: str
    expiry_days: Optional[int] = None
    optional_mso_attrs: Optional[dict] = None
    trust_framework: Optional[str] = ""
    assurance_level: Optional[str] = ""
    nbf_delta: Optional[int] = 0  # Offset in seconds from `iat` for `nbf`; defaults to 0, i.e. `nbf` == `iat`.

    # Forces the JWT expiry ("exp"), setting it equal to the credential expiry (expiry_days).
    # WARNING: for security reasons "exp" should be shorter.
    force_jwt_exp: Optional[bool] = False


    @field_validator('nbf_delta', mode='before')
    @classmethod
    def nbf_delta_default(cls, v):
        if v is None: return 0
        return v