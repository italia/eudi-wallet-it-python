from enum import Enum
from typing import List
from pydantic import BaseModel


class VPSigningAlgResponseSupported(str, Enum):
    eddsa = "EdDSA"
    es256k = "ES256K"


class VPAlgorithmSchema(BaseModel):
    alg: List[VPSigningAlgResponseSupported]


class VPFormat(BaseModel):
    jwt_vp_json: VPAlgorithmSchema
