from pydantic import BaseModel, Field, HttpUrl

from pyeudiw.openid4vp.schemas.response import ResponseMode
from pyeudiw.presentation_exchange.schemas.oid4vc_presentation_definition import PresentationDefinition


class AuthorizationConfig(BaseModel):
    url_scheme: str
    scopes: list[str]
    default_acr_value: HttpUrl
    # expiration_time must be greater than 0
    expiration_time: int = Field(..., gt=0)
    aud: str
    response_mode: ResponseMode
    presentation_definition: PresentationDefinition
