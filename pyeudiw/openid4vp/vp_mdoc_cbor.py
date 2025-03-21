from datetime import datetime, timezone
from pymdoccbor.mdoc.verifier import MdocCbor
from pyeudiw.openid4vp.exceptions import MdocCborValidationError
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser

class VpMDocCbor(BaseVPParser):
    def _is_expired(self, mdoc: MdocCbor) -> bool:
        for document in mdoc.documents:
            try:
                if document.issuersigned.issuer_auth.payload_as_dict['validityInfo']['validUntil'] < datetime.now(timezone.utc):
                    return True
            except KeyError:
                return True
        return False
    
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

        # Materiale crittografico da validare con trust evaluator
        # mdoc.issuersigned.issuer_auth.x509_certificates

        if mdoc.verify() == False:
            raise MdocCborValidationError("Signature is invalid")
        
        if self._is_expired(mdoc):
            raise MdocCborValidationError("Credential is expired")
        
    def parse(self, token: str) -> None:
        mdoc = MdocCbor()
        mdoc.loads(data=token)
        mdoc.verify()

        return mdoc.disclosure_map