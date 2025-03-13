import logging
from typing import Union
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustParameterData
from pyeudiw.trust.handler.exceptions import InvalidTrustHandlerConfiguration
from pyeudiw.x509.verify import (
    verify_x509_attestation_chain, 
    get_expiry_date_from_x5c, 
    der_list_to_pem_list, 
    pem_list_to_der_list, 
    get_x509_dns_name
)

logger = logging.getLogger(__name__)

class X509Hanlder(TrustHandlerInterface):
    """
    X509Handler is a trust handler implementation that extracts trust material from x509 certificates.
    """
    def __init__(
        self, 
        client_id: str, 
        relying_party_certificate_chains_by_ca: dict[str, Union[list[bytes], list[str]]],
        private_keys: list[dict[str, str]],
        **kwargs
    ):  
        if not relying_party_certificate_chains_by_ca:
            raise InvalidTrustHandlerConfiguration("No x509 certificate chains provided")
        
        if client_id not in relying_party_certificate_chains_by_ca:
            raise InvalidTrustHandlerConfiguration("No x509 certificate chain provided for the relying party")

        self.client_id = client_id

        self.relying_party_certificate_chains_by_ca = {}

        for k, v in relying_party_certificate_chains_by_ca.items():
            dns_name = get_x509_dns_name(v)
            
            if not dns_name in k:
                raise InvalidTrustHandlerConfiguration(f"Invalid x509 certificate: expected {k} got {dns_name}")

            chain = pem_list_to_der_list(v) if type(v[0]) == str and v[0].startswith("-----BEGIN CERTIFICATE-----") else v
            self.relying_party_certificate_chains_by_ca[k] = chain

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
                x5c=der_list_to_pem_list(chain),
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
