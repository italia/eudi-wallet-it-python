from typing import Any, Dict, List

from pydantic import BaseModel, HttpUrl, field_validator
from pydantic_core.core_schema import FieldValidationInfo

from pyeudiw.jwk.schema import JwksSchema

_default_algorithms = {
    "authorization_signed_response_alg": [
        "RS256",
        "ES256"
    ],
    "authorization_encrypted_response_alg": [
        "RSA-OAEP",
        "RSA-OAEP-256",
    ],
    "authorization_encrypted_response_enc": [
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ],
    "id_token_signed_response_alg": [
        "RS256",
        "ES256"
    ],
    "id_token_encrypted_response_alg": [
        "RSA-OAEP",
        "RSA-OAEP-256",
    ],
    "id_token_encrypted_response_enc": [
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ]
}


class WalletRelyingParty(BaseModel):
    application_type: str
    client_id: HttpUrl
    client_name: str
    jwks: JwksSchema
    contacts: List[str]
    request_uris: List[HttpUrl]
    redirect_uris: List[HttpUrl]
    default_acr_values: List[HttpUrl]
    vp_formats: Dict[str, Dict[str, List[str]]]
    presentation_definitions: List[Any]
    default_max_age: int
    authorization_signed_response_alg: List[str]
    authorization_encrypted_response_alg: List[str]
    authorization_encrypted_response_enc: List[str]
    subject_type: str
    require_auth_time: bool
    id_token_signed_response_alg: List[str]
    id_token_encrypted_response_alg: List[str]
    id_token_encrypted_response_enc: List[str]

    @classmethod
    def _get_algorithms_supported(cls, name: str, info: FieldValidationInfo) -> list[str]:
        if not info.context:
            return _default_algorithms[name]
        return info.context.get(name, _default_algorithms[name])

    @classmethod
    def _check_algorithms(cls, algorithms: list[str], name: str, info: FieldValidationInfo):
        supported_algorithms = WalletRelyingParty._get_algorithms_supported(
            name, info)
        for alg in algorithms:
            if alg not in supported_algorithms:
                raise ValueError(
                    f"Unsupported algorithm: {alg} for {name}. "
                    f"Supported algorithms: {supported_algorithms}."
                )
        return algorithms

    @field_validator(
        "authorization_signed_response_alg",
        "authorization_encrypted_response_alg",
        "authorization_encrypted_response_enc",
        "id_token_signed_response_alg",
        "id_token_encrypted_response_alg",
        "id_token_encrypted_response_enc"
    )
    @classmethod
    def check_alg(cls, value, info: FieldValidationInfo):
        return WalletRelyingParty._check_algorithms(
            value,
            info.field_name,
            info
        )
