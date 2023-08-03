from typing import List, Dict, Any

from pydantic import BaseModel, HttpUrl

from pyeudiw.jwk.schema import JwksSchema


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
    # TODO: check if the following lists can be narrowed down to a list of Literals
    authorization_signed_response_alg: List[str]
    authorization_encrypted_response_alg: List[str]
    authorization_encrypted_response_enc: List[str]
    subject_type: str
    require_auth_time: bool
    id_token_signed_response_alg: List[str]
    id_token_encrypted_response_alg: List[str]
    id_token_encrypted_response_enc: List[str]

