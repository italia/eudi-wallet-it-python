from pydantic import BaseModel
from pyeudiw.federation.schemas.wallet_relying_party import WalletRelyingParty
from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.jwk.schemas.public import JwkSchema
from pyeudiw.satosa.schemas.endpoint import EndpointsConfig
from pyeudiw.satosa.schemas.qrcode import QRCode
from pyeudiw.satosa.schemas.response import ResponseConfig
from pyeudiw.satosa.schemas.autorization import AuthorizationConfig
from pyeudiw.satosa.schemas.user_attributes import UserAttributesConfig
from pyeudiw.satosa.schemas.ui import UiConfig
from pyeudiw.storage.schemas.storage import Storage
from pyeudiw.trust.model import TrustModuleConfiguration_T


class PyeudiwBackendConfig(BaseModel):
    ui: UiConfig
    endpoints: EndpointsConfig
    qrcode: QRCode
    response_code: ResponseConfig
    jwt: JWTConfig
    authorization: AuthorizationConfig
    user_attributes: UserAttributesConfig
    network: dict
    trust: dict[str, TrustModuleConfiguration_T]
    metadata_jwks: list[JwkSchema]
    storage: Storage
    metadata: WalletRelyingParty
