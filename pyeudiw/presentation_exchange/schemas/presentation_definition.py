from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel


class InputDescriptor(BaseModel):
    id: str
    name: Optional[str] = None
    purpose: Optional[str] = None
    format: Optional[str | dict[str, Any]] = None
    jwt: Optional[Dict[Literal["alg"], List[str]]] = None
    mso_mdoc: Optional[Dict[Literal["alg"], List[str]]] = None
    constraints: Optional[Dict[str, Any]] = None


class PresentationDefinition(BaseModel):
    id: str
    input_descriptors: List[InputDescriptor]
