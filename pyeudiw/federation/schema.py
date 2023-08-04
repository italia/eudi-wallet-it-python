from typing import Optional

from pydantic import BaseModel


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
        if payload["iss"] != payload["sub"]:
            return True
    except Exception:
        return False


def is_ec(payload: dict) -> bool:
    try:
        ESSchema(**payload)
        return False
    except Exception:
        return True
