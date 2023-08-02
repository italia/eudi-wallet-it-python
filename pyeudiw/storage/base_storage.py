class BaseStorage(object):
    def init_session(self, document_id: str, dpop_proof: dict, attestation: dict):
        NotImplementedError()

    def update_request_object(self, document_id: str, nonce: str, state: str | None, request_object: dict):
        NotImplementedError()

    def update_response_object(self, nonce: str, state: str | None, response_object: dict):
        NotImplementedError()
