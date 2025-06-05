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
                

class WalletMetadata(BaseModel):
    wallet_metadata: Optional[VPFormatsSupported] = None
    wallet_nonce: Optional[str] = None
