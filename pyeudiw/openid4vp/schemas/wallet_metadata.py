from typing import Optional, Literal, Dict, List
from pydantic import BaseModel

# TODO: Move this to a global file
_default_supported_algorithms = Literal[
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

class VPFormatsSupported(BaseModel):
    vp_formats_supported: Dict[str, Dict[str, List[_default_supported_algorithms]]]
    client_id_prefixes_supported: Optional[List[str]] = None

class WalletMetadata(BaseModel):
    wallet_metadata: Optional[VPFormatsSupported] = None
    wallet_nonce: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    response_types_supported: Optional[List[str]] = None
    response_modes_supported: Optional[List[str]] = None
