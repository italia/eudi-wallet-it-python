import ssl
import logging
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustParameterData
from pyeudiw.jwk.parse import parse_key_from_x5c
from pyeudiw.x509.verify import verify_x509_anchor, to_pems_list, get_expiry_date_from_x5c

logger = logging.getLogger(__name__)

class X509Hanlder(TrustHandlerInterface):
    """
    X509Handler is a trust handler implementation that extracts trust material from x509 certificates.
    """
    def __init__(self, client_id, **kwargs):
        self.client_id = client_id

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        pem = ssl.get_server_certificate((issuer, 443))

        if not verify_x509_anchor(pem):
            logger.error(f"Invalid x509 anchor certificate for issuer {issuer}")
            return trust_source
        
        pems = to_pems_list(pem)

        try:
            jwk = parse_key_from_x5c(pems)
        except Exception as e:
            logger.error(f"Failed to parse x509 certificate chain for issuer {issuer}: {e}")
            return trust_source
        
        exp = get_expiry_date_from_x5c(pems)

        trust_source.add_trust_param(
            "x509",
            TrustParameterData(
                attribute_name="x5c",
                x5c=pems,
                expiration_date=exp,
                jwks=[jwk.as_dict()],
                trust_handler_name=self.name,
            )
        )

        return trust_source
    
    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        return trust_source
