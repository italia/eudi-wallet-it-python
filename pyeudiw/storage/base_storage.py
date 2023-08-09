class BaseStorage(object):
    def init_session(self, document_id: str, *, session_id: str, state: str):
        NotImplementedError()

    def add_dpop_proof_and_attestation(self, document_id: str, *, dpop_proof: dict, attestation: dict) -> str:
        NotImplementedError()

    def set_finalized(self, document_id: str):
        NotImplementedError()

    def update_request_object(self, document_id: str, request_object: dict):
        NotImplementedError()

    def update_response_object(self, nonce: str, state: str | None, response_object: dict):
        NotImplementedError()

    def exists_by_state_and_session_id(self, *, state: str, session_id: str | None = None) -> bool:
        NotImplementedError()

    def get_by_state_and_session_id(self, *, state: str, session_id: str | None = None):
        NotImplementedError()
