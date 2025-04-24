from datetime import datetime, timezone
from pymdoccbor.mdoc.verifier import MdocCbor
from cryptography.hazmat.primitives import serialization
from pyeudiw.x509.verify import get_issuer_from_x5c
from pyeudiw.status_list.helper import StatusListTokenHelper
from pyeudiw.openid4vp.exceptions import MdocCborValidationError, VPRevoked
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
        
        try:
            for document in mdoc.documents:
                x5c = [
                    cert.public_bytes(encoding=serialization.Encoding.PEM).decode() 
                    for cert in document.issuersigned.issuer_auth.x509_certificates
                ]

                self.trust_evaluator.get_public_keys(
                    get_issuer_from_x5c(x5c),
                    {"x5c": x5c}
                )
        except Exception as e:
            raise MdocCborValidationError(f"Error validating keys: {e}")
        
        if self._is_expired(mdoc):
            raise MdocCborValidationError("Credential is expired")
        
        if mdoc.status:
            status_list = StatusListTokenHelper.from_status(mdoc.status)
            if status_list.is_expired() or \
               status_list.get_status(mdoc.status["status_list"]["idx"]) > 0:
                raise VPRevoked(
                    "Status list indicates that the token is revoked"
                )
        
    def parse(self, token: str) -> None:
        mdoc = MdocCbor()
        mdoc.loads(data=token)
        mdoc.verify()

        return mdoc.disclosure_map