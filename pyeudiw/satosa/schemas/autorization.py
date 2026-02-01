from typing import Optional

from pydantic import BaseModel, Field, HttpUrl

from pyeudiw.duckle_ql.credential import CredentialsRequest
from pyeudiw.satosa.backends.openid4vp.schemas import ResponseMode


class AuthorizationConfig(BaseModel):
    url_scheme: str
    scopes: list[str]
    default_acr_value: HttpUrl
    # expiration_time must be greater than 0
    expiration_time: int = Field(..., gt=0)
    aud: str
    response_mode: ResponseMode
    dcql_query: Optional[CredentialsRequest] = None
