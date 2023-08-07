from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class InputDescriptorJwt(BaseModel):
    alg: List[str]


class MsoMdoc(BaseModel):
    alg: List[str]


class FormatSchema(BaseModel):
    jwt: Optional[InputDescriptorJwt] = None
    mso_mdoc: Optional[MsoMdoc] = None
    constraints: Optional[Dict[str, Any]] = None


class InputDescriptor(BaseModel):
    id: str
    name: Optional[str] = None
    purpose: Optional[str] = None
    format: Optional[str | FormatSchema] = None


class PresentationDefinition(BaseModel):
    id: str
    input_descriptors: List[InputDescriptor]
