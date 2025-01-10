from pydantic import BaseModel, Field, HttpUrl


class AuthorizationConfig(BaseModel):
    url_scheme: str
    scopes: list[str]
    default_acr_value: HttpUrl
    aud: str
    expiration_time: int = Field(..., gt=0)  # expiration_time must be greater than 0
