from typing import Optional, List, Literal, Dict, Any

from pydantic import BaseModel


class InputDescriptor(BaseModel):
    id: str
    name: Optional[str] = None
    purpose: Optional[str] = None
    # TODO: narrow down format type and possibly use a more specific model
    format: Optional[str | dict[str, Any]] = None
    jwt: Optional[Dict[Literal["alg"], List[str]]] = None
    mso_mdoc: Optional[Dict[Literal["alg"], List[str]]] = None
    constraints: Optional[Dict[str, Any]] = None


class PresentationDefinition(BaseModel):
    id: str
    input_descriptors: List[InputDescriptor]
