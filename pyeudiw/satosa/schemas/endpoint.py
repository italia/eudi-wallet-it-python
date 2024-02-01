from pydantic import BaseModel, field_validator


class EndpointsConfig(BaseModel):
    pre_request: str
    response: str
    request: str
    entity_configuration: str
    status: str
    get_response: str

    @field_validator('pre_request', 'response', 'request', 'entity_configuration', 'status', 'get_response')
    def must_start_with_slash(cls, v):
        if not v.startswith('/'):
            raise ValueError(f'{v} must start with "/"')
        return v
