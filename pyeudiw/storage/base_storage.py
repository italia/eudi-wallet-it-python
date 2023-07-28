class BaseStorage(object):
    def init_session(self, dpop_proof: dict, attestation: dict):
        NotImplementedError()

    def update_request_object(self, document_id: str, request_object: dict):
        NotImplementedError()

    def update_response_object(self, nonce: str, state: str, response_object: dict):
        NotImplementedError()
