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
    get_leaf_x509_dns_name,
    get_root_x509_dns_name
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

        self.relying_party_certificate_chains_by_ca = {}

        for k, v in relying_party_certificate_chains_by_ca.items():
            leaf_dns_name = get_leaf_x509_dns_name(v)
            root_dns_name = get_root_x509_dns_name(v)
            
            if not root_dns_name in k:
                raise InvalidTrustHandlerConfiguration(f"Invalid x509 certificate: expected {k} got {root_dns_name}")
                    
            if leaf_dns_name not in client_id:
                raise InvalidTrustHandlerConfiguration("Invalid x509 chain: not associated with the relying party")

            chain = pem_list_to_der_list(v) if type(v[0]) == str and v[0].startswith("-----BEGIN CERTIFICATE-----") else v

            if verify_x509_attestation_chain(chain):
                self.relying_party_certificate_chains_by_ca[k] = chain
            else:
                logger.error(f"Invalid x509 anchor certificate for CA {k}: the chain will be removed")

        self.private_keys = private_keys

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        # Return the first valid chain
        for ca, chain in self.relying_party_certificate_chains_by_ca.items():    
            if not verify_x509_attestation_chain(chain):
                logger.error(f"Invalid x509 anchor certificate for CA {ca}: the chain will be removed")
                del self.relying_party_certificate_chains_by_ca[ca]
                continue
            
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
        
        return trust_source
    
    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        return trust_source
