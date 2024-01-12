from enum import Enum
from typing import List
from pyeudiw.jwk.schemas.jwk import JwksSchema
from pydantic import BaseModel, HttpUrl, PositiveInt
from pyeudiw.openid4vp.schemas.vp_formats import VpFormats
from pyeudiw.presentation_exchange.schemas.oid4vc_presentation_definition import PresentationDefinition


class AcrValuesSupported(str, Enum):
    spid_l1 = "https://www.spid.gov.it/SpidL1"
    spid_l2 = "https://www.spid.gov.it/SpidL2"
    spid_l3 = "https://www.spid.gov.it/SpidL3"


class EncryptionAlgValuesSupported(str, Enum):
    rsa_oaep = "RSA-OAEP"
    ras_oaep_256 = "RSA-OAEP-256"
    ecdh_es = "ECDH-ES"
    ecdh_es_a128kw = "ECDH-ES+A128KW"
    ecdh_es_a192kw = "ECDH-ES+A192KW"
    ecdh_es_a256kw = "ECDH-ES+A256KW"


class EncryptionEncValuesSupported(str, Enum):
    a128cbc_hs256 = "A128CBC-HS256"
    a192cbc_hs384 = "A192CBC-HS384"
    a256cbc_hs512 = "A256CBC-HS512"
    a128gcm = "A128GCM"
    a192gcm = "A192GCM"
    a256gcm = "A256GCM"


class SigningAlgValuesSupported(str, Enum):
    es256 = "ES256"
    es384 = "ES384"
    es512 = "ES512"
    rs256 = "RS256"
    rs384 = "RS384"
    rs512 = "RS512"


class AuthorizationSignedResponseAlg(str, Enum):
    rs256 = "RS256"
    rs384 = "RS384"
    rs512 = "RS512"
    es256 = "ES256"
    es384 = "ES384"
    es512 = "ES512"


class WalletRelyingParty(BaseModel):
    application_type: str
    client_id: HttpUrl
    client_name: str
    jwks: JwksSchema
    contacts: List[str]
    request_uris: List[HttpUrl]
    redirect_uris: List[HttpUrl]
    default_acr_values: List[HttpUrl]
    presentation_definition: PresentationDefinition
    authorization_signed_response_alg: List[AuthorizationSignedResponseAlg]
    authorization_encrypted_response_alg: List[EncryptionAlgValuesSupported]
    authorization_encrypted_response_enc: List[EncryptionEncValuesSupported]
    subject_type: str
    require_auth_time: bool
    id_token_encrypted_response_alg: List[EncryptionAlgValuesSupported]
    id_token_encrypted_response_enc: List[EncryptionEncValuesSupported]
    id_token_signed_response_alg: List[SigningAlgValuesSupported]
    default_acr_values: List[AcrValuesSupported]
    default_max_age: PositiveInt
    vp_formats: VpFormats
