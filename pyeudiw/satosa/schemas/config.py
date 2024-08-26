from pydantic import BaseModel
from pyeudiw.jwk.schemas.jwk import JwkSchema
from pyeudiw.satosa.schemas.endpoint import EndpointsConfig
from pyeudiw.satosa.schemas.qrcode import QRCode
from pyeudiw.satosa.schemas.response import ResponseConfig
from pyeudiw.satosa.schemas.autorization import AuthorizationConfig
from pyeudiw.satosa.schemas.user_attributes import UserAttributesConfig
from pyeudiw.federation.schemas.federation_configuration import FederationConfig
from pyeudiw.federation.schemas.wallet_relying_party import WalletRelyingParty
from pyeudiw.satosa.schemas.ui import UiConfig
from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.storage.schemas.storage import StorageConfig


class PyeudiwBackendConfig(BaseModel):
    module: str
    name: str
    config: dict

    ui: UiConfig
    endpoints: EndpointsConfig
    qrcode: QRCode
    response_code: ResponseConfig
    jwt: JWTConfig
    authorization: AuthorizationConfig
    user_attributes: UserAttributesConfig
    network: dict
    federation: FederationConfig
    metadata_jwks: list[JwkSchema]
    storage: StorageConfig
    metadata: WalletRelyingParty
