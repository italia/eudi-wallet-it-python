from typing import Union

from pydantic import BaseModel, field_validator, Field

_CONFIG_ENDPOINT_KEYS = ["module", "class", "path"]


class EndpointsConfig(BaseModel):
    pre_request: Union[str, dict]
    response: Union[str, dict]
    request: Union[str, dict]
    status: Union[str, dict]
    get_response: Union[str, dict]

    @field_validator("pre_request", "response", "request", "status", "get_response")
    def must_start_with_slash(cls, v):
        if isinstance(v, str) and not v.startswith("/"):
            raise ValueError(f"Endpoints: {v} must start with '/'")
        elif isinstance(v, dict):
            if not v["path"].startswith("/"):
                raise ValueError(f"Endpoints: {v['path']} must start with '/'")
        return v

    @field_validator("response", "request")
    def must_start_with_slash_path(cls, v):
        endpoint_value = v
        if isinstance(v, dict):
            endpoint_value = v.get("path", None)

        if not endpoint_value or not isinstance(endpoint_value, str):
            raise ValueError(f"Invalid config endpoint structure for {endpoint_value}")

        if not endpoint_value.startswith("/"):
            raise ValueError(f"{endpoint_value} must start with '/'")
        return v

    @field_validator("response", "request")
    def validate_dict_keys(cls, v):
        if isinstance(v, dict):
            if set(_CONFIG_ENDPOINT_KEYS) != set(v.keys()):
                raise ValueError(f"Invalid config endpoint structure for {v}")
        return v

class EndpointDefConfig(BaseModel):
    module: str
    class_: str = Field(..., alias="class")
    path: str