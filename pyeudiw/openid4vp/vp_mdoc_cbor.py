from pymdoccbor.mdoc.verifier import MdocCbor
from datetime import datetime
from pyeudiw.openid4vp.exceptions import MdocCborValidationError
import logging

logger = logging.getLogger(__name__)


class VpMDocCbor:
    def __init__(self, data: str) -> None:
        self.data = data
        self.mdoc = MdocCbor()
        self.parse_digital_credential()

    def get_documents(self) -> dict:
        return self.mdoc.data_as_cbor_dict["documents"]
    
    def is_revoked(self) -> bool:
        return False
    
    def is_expired(self) -> bool:
        _val_until: str = ""
        try:
            _val_until = self.mdoc.data_as_cbor_dict()["issuerSigned"]["issuerAuth"]["validityInfo"].get("validUntil")
        except KeyError as e:
            logger.error(f'Unconsitent issuerSigned schema ["issuerSigned"]["issuerAuth"]["validityInfo"], {e}, in mdoc cbor: {self.mdoc.data_as_cbor_dict()}')
        if _val_until:
            exp_date = datetime.fromisoformat(_val_until)
        else:
            logger.warning(f"Missing issuerSigned velidUntil in mdoc cbor: {self.mdoc.data_as_cbor_dict()}")

        return exp_date < datetime.now()
    
    def verify_signature(self) -> None:
        if self.mdoc.verify() == False:
            raise MdocCborValidationError("Signature is invalid")
        
    def parse_digital_credential(self) -> None:
        self.mdoc.loads(data=self.data)

    def _detect_vp_type(self) -> str:
        return "mdoc_cbor"
