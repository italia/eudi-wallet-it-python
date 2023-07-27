from pydantic import BaseModel

class Descriptor(BaseModel):
    id: str
    path: str
    format: str

class PresentationSubmission(BaseModel):
    definition_id: str
    id: str
    descriptor_map: list[Descriptor]

class Response(BaseModel):
    state: str
    vp_token: str | list[str]
    presentation_submission: PresentationSubmission
    