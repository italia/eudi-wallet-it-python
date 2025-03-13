import ssl
import logging
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustParameterData
from pyeudiw.x509.verify import verify_x509_attestation_chain, get_expiry_date_from_x5c

logger = logging.getLogger(__name__)

class X509Hanlder(TrustHandlerInterface):
    """
    X509Handler is a trust handler implementation that extracts trust material from x509 certificates.
    """
    def __init__(
        self, 
        client_id: str, 
        relying_party_certificate_chains_by_ca: dict[str, list[bytes]],
        private_keys: list[dict[str, str]],
        **kwargs
    ):
        self.client_id = client_id
        self.relying_party_certificate_chains_by_ca = relying_party_certificate_chains_by_ca
        self.private_keys = private_keys

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        issuer = issuer if issuer != "__internal__" else self.client_id
        chain = self.relying_party_certificate_chains_by_ca.get(issuer)

        if not chain:
            logger.error(f"Invalid x509 anchor certificate for issuer {issuer}")
            return trust_source

        if not verify_x509_attestation_chain(chain):
            logger.error(f"Invalid x509 anchor certificate for issuer {issuer}")
            return trust_source
        
        exp = get_expiry_date_from_x5c(chain)

        trust_source.add_trust_param(
            "x509",
            TrustParameterData(
                attribute_name="x5c",
                x5c=chain,
                expiration_date=exp,
                jwks=self.private_keys,
                trust_handler_name=self.name,
            )
        )

        return trust_source
    
    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        return trust_source
