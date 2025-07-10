from typing import Optional, Dict, List
from urllib.parse import urlparse

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
    authorization_endpoint: Optional[str] = None
    request_object_signing_alg_values_supported: Optional[List[str]] = None
    response_types_supported: Optional[list[str]] = None
    response_modes_supported: Optional[list[str]] = None

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

    @field_validator("authorization_endpoint", mode="before")
    def validate_authorization_endpoint(cls, v):
        try:
            parsed_redirect_uri = urlparse(v)
            if not parsed_redirect_uri.scheme or not parsed_redirect_uri.netloc or not parsed_redirect_uri.path:
                raise ValueError("Invalid value for authorization_endpoint")
            return v
        except Exception:
            raise ValueError("Invalid value for authorization_endpoint")

class WalletPostRequest(BaseModel):
    wallet_metadata: Optional[WalletMetadata] = None
    wallet_nonce: Optional[str] = None