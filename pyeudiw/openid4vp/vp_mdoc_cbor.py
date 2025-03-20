from datetime import datetime
from pymdoccbor.mdoc.verifier import MdocCbor
from pyeudiw.openid4vp.exceptions import MdocCborValidationError
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser

class VpMDocCbor(BaseVPParser):
    def _is_expired(self, mdoc: MdocCbor) -> bool:
        return False
        #Todo: Implement this method

        exp_date = datetime.fromisoformat(
            mdoc.data_as_cbor_dict["issuerSigned"]["issuerAuth"]["validityInfo"]["validUntil"]
        )

        return exp_date < datetime.now()
    
    def _is_revoked(self) -> bool:
        # TODO - revocation check here, using status list
        return False

    def validate(
            self, 
            token: str, 
            verifier_id: str, 
            verifier_nonce: str
        ) -> None:
        mdoc = MdocCbor()
        mdoc.loads(data=token)

        if mdoc.verify() == False:
            raise MdocCborValidationError("Signature is invalid")
        
        if self._is_expired(mdoc):
            raise MdocCborValidationError("Credential is expired")
        
    def parse(self, token: str) -> None:
        mdoc = MdocCbor()
        mdoc.loads(data=token)

        return {}
    
        #Todo: Implement this method

        mdoc.data_as_cbor_dict["documents"]
        return 
