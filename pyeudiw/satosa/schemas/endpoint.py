from typing import Union
from pydantic import BaseModel


class EndpointsConfig(BaseModel):
    pre_request: str
    response: Union[str, dict]
    request: Union[str, dict]
    entity_configuration: str
    status: str
    get_response: str
