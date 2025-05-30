from pydantic import BaseModel, root_validator, model_validator

from pyeudiw.federation.schemas.openid_credential_verifier import (
    OpenIDCredentialVerifier,
)
from pyeudiw.jwk.schemas.public import JwkSchema
from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.satosa.schemas.autorization import AuthorizationConfig
from pyeudiw.satosa.schemas.endpoint import EndpointsConfig
from pyeudiw.satosa.schemas.metadata import Metadata
from pyeudiw.satosa.schemas.response import ResponseConfig
from pyeudiw.satosa.schemas.ui import UiConfig
from pyeudiw.satosa.schemas.user_attributes import UserAttributesConfig
from pyeudiw.storage.schemas.storage import Storage
from pyeudiw.trust.model import TrustModuleConfiguration_T


class PyeudiwBackendConfig(BaseModel):
    ui: UiConfig
    endpoints: EndpointsConfig
    response_code: ResponseConfig
    jwt: JWTConfig
    authorization: AuthorizationConfig
    user_attributes: UserAttributesConfig
    network: dict
    trust: dict[str, TrustModuleConfiguration_T]
    metadata_jwks: list[JwkSchema]
    storage: Storage
    metadata: OpenIDCredentialVerifier

class PyeudiwFrontendConfig(BaseModel):
    jwt: JWTConfig
    metadata: Metadata

    @model_validator(mode="before")
    def check_config(cls, values):
        jwt = values.get("jwt")
        if jwt.access_token_exp:
            raise ValueError("Field 'jwt.access_token_exp' must be provided and non-empty.")
        if jwt.refresh_token_exp:
            raise ValueError("Field 'jwt.refresh_token_exp' must be provided and non-empty.")
        if jwt.par_exp:
            raise ValueError("Field 'jwt.par_exp' must be provided and non-empty.")

        return values
