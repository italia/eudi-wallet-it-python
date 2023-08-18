import datetime


# TODO: add all those defined methods in mongodb storage
class BaseStorage(object):
    def init_session(self, document_id: str, dpop_proof: dict, attestation: dict):
        raise NotImplementedError()

    def update_request_object(self, document_id: str, nonce: str, state: str | None, request_object: dict):
        raise NotImplementedError()

    def update_response_object(self, nonce: str, state: str | None, response_object: dict):
        raise NotImplementedError()

    def get_trust_attestation(self, entity_id: str):
        raise NotImplementedError()

    def get_trust_anchor(self, entity_id: str):
        raise NotImplementedError()

    def has_trust_attestation(self, entity_id: str):
        raise NotImplementedError()

    def has_trust_anchor(self, entity_id: str):
        raise NotImplementedError()

    def add_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        raise NotImplementedError()

    def add_trust_anchor(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        raise NotImplementedError()

    def update_trust_attestation(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        raise NotImplementedError()

    def update_trust_anchor(self, entity_id: str, trust_chain: list[str], exp: datetime) -> str:
        raise NotImplementedError()
