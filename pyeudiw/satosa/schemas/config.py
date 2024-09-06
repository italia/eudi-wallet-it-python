from pydantic import BaseModel
from pyeudiw.jwk.schemas.public import JwkSchema
from pyeudiw.satosa.schemas.endpoint import EndpointsConfig
from pyeudiw.satosa.schemas.qrcode import QRCode
from pyeudiw.satosa.schemas.autorization import AuthorizationConfig
from pyeudiw.satosa.schemas.user_attributes import UserAttributesConfig
from pyeudiw.federation.schemas.federation_configuration import FederationConfig
from pyeudiw.federation.schemas.wallet_relying_party import WalletRelyingParty
from pyeudiw.satosa.schemas.ui import UiConfig
from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.storage.schemas.storage import Storage


class PyeudiwBackendConfig(BaseModel):
    ui: UiConfig
    endpoints: EndpointsConfig
    qrcode: QRCode
    jwt: JWTConfig
    authorization: AuthorizationConfig
    user_attributes: UserAttributesConfig
    network: dict
    federation: FederationConfig
    metadata_jwks: list[JwkSchema]
    storage: Storage
    metadata: WalletRelyingParty
