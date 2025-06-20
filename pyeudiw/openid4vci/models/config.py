from typing import Optional

from pydantic import BaseModel

from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.satosa.schemas.credential_configurations import CredentialConfigurationsConfig
from pyeudiw.satosa.schemas.endpoint import EndpointDefConfig
from pyeudiw.satosa.schemas.metadata import Metadata
from pyeudiw.storage.schemas.storage import Storage


class PyeudiwFrontendConfig(BaseModel):
    jwt: JWTConfig
    metadata: Metadata
    user_storage: Storage
    credential_storage: Storage
    endpoints: dict[str, EndpointDefConfig]
    credential_configurations: Optional[CredentialConfigurationsConfig] = None