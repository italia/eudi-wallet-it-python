from typing import Optional

from pydantic import BaseModel, Field, HttpUrl

from pyeudiw.duckle_ql.credential import CredentialsRequest
from pyeudiw.satosa.backends.openid4vp.schemas import ResponseMode


class AuthorizationConfig(BaseModel):
    url_scheme: str
    # Not part of OpenID4VP; required for the SATOSA bridge to the upstream IdP.
    # When building AuthenticationInformation for the IdP (SAML/OIDC), the VP response
    # typically has no acr/amr, so this fallback is used. Choose a value matching
    # your IdP's expected authentication context (e.g. https://www.spid.gov.it/SpidL2).
    default_acr_value: HttpUrl
    # expiration_time must be greater than 0
    expiration_time: int = Field(..., gt=0)
    aud: str
    response_mode: ResponseMode
    dcql_query: Optional[CredentialsRequest] = None
