from typing import Optional, Literal, Dict, List
from pydantic import BaseModel, field_validator

# TODO: Move this to a global file
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

class WalletMetadata(BaseModel):
    vp_formats_supported: Dict[str, Dict[str, List[str]]]
    alg_values_supported: Optional[List[str]] = None
    client_id_prefixes_supported: Optional[List[str]] = None

    @field_validator("alg_values_supported", mode="before")
    def validate_alg_values_supported(cls, v):
        if isinstance(v, str) and v in _default_supported_algorithms:
            return [v]
        elif isinstance(v, list):
            return [alg for alg in v if alg in _default_supported_algorithms]
        elif v is None:
            return _default_supported_algorithms
        else:
            raise ValueError("Invalid value for alg_values_supported")

class WalletPostRequest(BaseModel):
    wallet_metadata: Optional[WalletMetadata] = None
    wallet_nonce: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    response_types_supported: Optional[List[str]] = None
    response_modes_supported: Optional[List[str]] = None
