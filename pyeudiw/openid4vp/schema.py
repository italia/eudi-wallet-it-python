from pydantic import BaseModel

class DescriptorSchema(BaseModel):
    id: str
    path: str
    format: str

class PresentationSubmissionSchema(BaseModel):
    definition_id: str
    id: str
    descriptor_map: list[DescriptorSchema]

class ResponseSchema(BaseModel):
    state: str
    vp_token: str | list[str]
    presentation_submission: PresentationSubmissionSchema
    