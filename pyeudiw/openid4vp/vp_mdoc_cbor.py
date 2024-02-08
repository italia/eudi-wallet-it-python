from pyeudiw.openid4vp.vp import Vp
from pymdoccbor.mdoc.verifier import MdocCbor

class VpMDocCbor(Vp):
    def __init__(self, data: str) -> None:
        self.data = data
        self.mdoc = MdocCbor()
        self.parse_digital_credential()
        
    def parse_digital_credential(self) -> None:
        self.mdoc.load(data=self.data)

    def verify(self, **kwargs) -> bool:
        return self.mdoc.verify()
    
    def _detect_vp_type(self) -> str:
        return "mdoc_cbor"