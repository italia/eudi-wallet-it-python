from pydantic import BaseModel, Field, HttpUrl

from pyeudiw.presentation_exchange.schemas.oid4vc_presentation_definition import PresentationDefinition


class AuthorizationConfig(BaseModel):
    url_scheme: str
    scopes: list[str]
    default_acr_value: HttpUrl
    aud: str
    expiration_time: int = Field(..., gt=0)  # expiration_time must be greater than 0
    presentation_definition: PresentationDefinition
