from typing import Union
from pydantic import BaseModel, field_validator

_CONFIG_ENDPOINT_KEYS=["module", "class", "path"]

class EndpointsConfig(BaseModel):
    pre_request: str
    response: Union[str, dict]
    request: Union[str, dict]
    entity_configuration: str
    status: str
    get_response: str

    @field_validator("pre_request", "entity_configuration", "status", "get_response")
    def must_start_with_slash(cls, v):
        if not v.startswith('/'):
            raise ValueError(f"{v} must start with '/'")
        return v
    
    @field_validator("response", "request")
    def must_start_with_slash_path(cls, v):
        endpoint_value = v
        if isinstance(v, dict):
            endpoint_value = v.get("path", None)
        
        if not endpoint_value or not isinstance(endpoint_value, str):
            raise ValueError(f"Invalid config endpoint structure for {endpoint_value}")

        if not endpoint_value.startswith('/'):
            raise ValueError(f"{endpoint_value} must start with '/'")
        return v
    
    @field_validator("response", "request")
    def validate_dict_keys(cls, v):
        if isinstance(v, dict):
            if set(_CONFIG_ENDPOINT_KEYS) != set(v.keys()):
                raise ValueError(f"Invalid config endpoint structure for {v}")
        return v