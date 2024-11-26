from pydantic import BaseModel


class DescriptorSchema(BaseModel):
    id: str
    path: str
    format: str


class PresentationSubmissionSchema(BaseModel):
    definition_id: str
    id: str
    descriptor_map: list[DescriptorSchema]