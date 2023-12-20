import datetime
from enum import Enum
from typing import Union
from .base_db import BaseDB

class TrustType(Enum):
    X509 = 0
    FEDERATION = 1

trust_type_map : dict = {
  TrustType.X509 : "x509",
  TrustType.FEDERATION: "federation"
}

trust_attestation_field_map : dict = {
  TrustType.X509 : "x5c",
  TrustType.FEDERATION: "chain"
}

trust_anchor_field_map : dict = {
  TrustType.X509 : "pem",
  TrustType.FEDERATION: "entity_configuration"
}

class BaseStorage(BaseDB):
        raise NotImplementedError()

    def is_connected(self) -> bool:
        raise NotImplementedError()

    def close(self) -> None:
        raise NotImplementedError()

    def add_dpop_proof_and_attestation(self, document_id, dpop_proof: dict, attestation: dict):
        raise NotImplementedError()

    def set_finalized(self, document_id: str):
        raise NotImplementedError()

    def update_request_object(self, document_id: str, request_object: dict) -> int:
        raise NotImplementedError()

    def update_response_object(self, nonce: str, state: str, response_object: dict) -> int:
        raise NotImplementedError()

    def get_trust_attestation(self, entity_id: str) -> Union[dict, None]:
        raise NotImplementedError()

    def get_trust_anchor(self, entity_id: str) -> Union[dict, None]:
        raise NotImplementedError()

    def has_trust_attestation(self, entity_id: str):
        raise NotImplementedError()

    def has_trust_anchor(self, entity_id: str):
        raise NotImplementedError()

    def add_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime, trust_type: TrustType) -> str:
        raise NotImplementedError()
    
    def add_trust_attestation_metadata(self, entity_id: str, metadata_type: str, metadata: dict) -> str:
        raise NotImplementedError()

    def add_trust_anchor(self, entity_id: str, entity_configuration: str, exp: datetime, trust_type: TrustType):
        raise NotImplementedError()

    def update_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime, trust_type: TrustType) -> str:
        raise NotImplementedError()

    def update_trust_anchor(self, entity_id: str, entity_configuration: str, exp: datetime, trust_type: TrustType) -> str:
        raise NotImplementedError()

    def exists_by_state_and_session_id(self, state: str, session_id: str = "") -> bool:
        raise NotImplementedError()

    def get_by_state(self, state: str):
        raise NotImplementedError()

    def get_by_nonce_state(self, state: str, nonce: str):
        raise NotImplementedError()

    def get_by_state_and_session_id(self, state: str, session_id: str = ""):
        raise NotImplementedError()

    def get_by_session_id(self, session_id: str):
        raise NotImplementedError()

    # TODO: create add_or_update for all the write methods
    def add_or_update_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime) -> str:
        raise NotImplementedError()
