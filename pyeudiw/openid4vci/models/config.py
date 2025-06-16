from pydantic import BaseModel, model_validator

from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.satosa.schemas.credential_configurations import CredentialConfigurationsConfig
from pyeudiw.satosa.schemas.endpoint import EndpointDefConfig
from pyeudiw.satosa.schemas.metadata import Metadata
from pyeudiw.storage.schemas.storage import UserStorage


class PyeudiwFrontendConfig(BaseModel):
    jwt: JWTConfig
    metadata: Metadata
    user_storage: UserStorage
    endpoints: dict[str, EndpointDefConfig]
    credential_configurations: CredentialConfigurationsConfig

    @model_validator(mode="before")
    def check_config(cls, values):
        jwt = values.get("jwt")
        if not jwt["access_token_exp"]:
            raise ValueError("Field 'jwt.access_token_exp' must be provided and non-empty.")
        if not jwt["refresh_token_exp"]:
            raise ValueError("Field 'jwt.refresh_token_exp' must be provided and non-empty.")
        if not jwt["par_exp"]:
            raise ValueError("Field 'jwt.par_exp' must be provided and non-empty.")

        return values