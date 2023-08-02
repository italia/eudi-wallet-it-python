from typing import List, Literal, Optional

from pydantic import BaseModel, field_validator

class ESSchema(BaseModel, extra='forbid'):
    exp: int
    iat: int
    iss: str
    sub: str
    jwks: dict
    source_endpoint: Optional[str] = None
    
def is_es(payload: dict) -> bool:
    try:
        ESSchema(**payload)
        return True
    except Exception as e:
        return False