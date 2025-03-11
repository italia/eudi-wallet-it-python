from pymdoccbor.mdoc.verifier import MdocCbor
from datetime import datetime
from pyeudiw.openid4vp.exceptions import MdocCborValidationError

class VpMDocCbor:
    def __init__(self, data: str) -> None:
        self.data = data
        self.mdoc = MdocCbor()
        self.parse_digital_credential()

    def get_credentials(self) -> dict:
        return self.mdoc.data_as_cbor_dict()["issuerSigned"]
    
    def get_doc_type(self) -> str:
        return self.mdoc.data_as_cbor_dict()["docType"]
    
    def is_revoked(self) -> bool:
        return False
    
    def is_expired(self) -> bool:
        exp_date = datetime.fromisoformat(
            self.mdoc.data_as_cbor_dict()["issuerSigned"]["issuerAuth"]["validityInfo"]["validUntil"]
        )

        return exp_date < datetime.now()
    
    def verify_signature(self) -> None:
        if self.mdoc.verify() == False:
            raise MdocCborValidationError("Signature is invalid")
        
    def parse_digital_credential(self) -> None:
        self.mdoc.load(data=self.data)

    def _detect_vp_type(self) -> str:
        return "mdoc_cbor"
