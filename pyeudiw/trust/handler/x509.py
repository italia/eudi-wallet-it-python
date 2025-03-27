import logging
from typing import Union
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustEvaluationType
from pyeudiw.trust.handler.exceptions import InvalidTrustHandlerConfiguration
from pyeudiw.jwk.parse import parse_pem, parse_x5c_keys
from pyeudiw.x509.verify import (
    verify_x509_attestation_chain, 
    get_expiry_date_from_x5c, 
    der_list_to_pem_list, 
    pem_list_to_der_list, 
    get_x509_info,
    get_trust_anchor_from_x5c
)

logger = logging.getLogger(__name__)

class X509Handler(TrustHandlerInterface):
    """
    X509Handler is a trust handler implementation that extracts trust material from x509 certificates.
    """
    def __init__(
        self, 
        client_id: str, 
        relying_party_certificate_chains_by_ca: dict[str, Union[list[bytes], list[str]]],
        private_keys: list[dict[str, str]],
        client_id_scheme: str = "x509_san_uri",
        **kwargs
    ):  
        self.client_id = client_id
        self.client_id_scheme = client_id_scheme

        if not relying_party_certificate_chains_by_ca:
            raise InvalidTrustHandlerConfiguration("No x509 certificate chains provided in the configuration")

        self.relying_party_certificate_chains_by_ca = {}

        for k, v in relying_party_certificate_chains_by_ca.items():
            root_dns_name = get_x509_info(v[-1])
            
            if not root_dns_name in k:
                raise InvalidTrustHandlerConfiguration(f"Invalid x509 certificate: expected {k} got {root_dns_name} instead of {k}")
            
            found_client_id = False

            for cert in v[:-1]:
                if get_x509_info(cert, self.client_id_scheme) == client_id:
                    found_client_id = True
                    break
                
            if not found_client_id:
                logger.error(f"Invalid x509 leaf certificate using CA {k}. Unmatching client id ({client_id}), the chain will be removed")

            chain = pem_list_to_der_list(v) if type(v[0]) == str and v[0].startswith("-----BEGIN CERTIFICATE-----") else v

            if verify_x509_attestation_chain(chain):
                self.relying_party_certificate_chains_by_ca[k] = chain
            else:
                logger.error(f"Invalid x509 certificate chain using CA {k}. Chain validation failed, the chain will be removed")

        self.private_keys = private_keys

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        # Return the first valid chain
        for ca, chain in self.relying_party_certificate_chains_by_ca.items():
            if not verify_x509_attestation_chain(chain):
                logger.error(f"Invalid x509 certificate chain using CA {ca}. Chain validation failed, the chain will be removed")
                del self.relying_party_certificate_chains_by_ca[ca]
                continue
            
            exp = get_expiry_date_from_x5c(chain)

            trust_source.add_trust_param(
                "x509",
                TrustEvaluationType(
                    attribute_name="x5c",
                    x5c=der_list_to_pem_list(chain),
                    expiration_date=exp,
                    jwks=self.private_keys,
                    trust_handler_name=self.name,
                )
            )

            return trust_source
        
        return trust_source
    
    def validate_trust_material(
        self, 
        x5c: list[str], 
        trust_source: TrustSourceData,
        db_engine: DBEngine
    ) -> dict[bool, TrustSourceData]:
        chain = pem_list_to_der_list(x5c)

        if len(chain) > 1 and not verify_x509_attestation_chain(chain):
            logger.error(f"Invalid x509 certificate chain. Chain validation failed")
            return False, trust_source

        issuer = get_trust_anchor_from_x5c(chain)

        try:
            trust_anchor = db_engine.get_trust_anchor(issuer)
        except Exception:
            logger.error(f"Invalid x509 certificate chain. Trust anchor not found")
            return False, trust_source
        
        anchor_x509 = trust_anchor.get("x509")

        if not anchor_x509:
            logger.error(f"Invalid x509 certificate chain. Trust anchor x509 not found")
            return False, trust_source
        
        issuer_pem = anchor_x509["pem"]

        try:
            issuer_jwk = parse_pem(issuer_pem)
            chain_jwks = parse_x5c_keys(x5c)
        except Exception as e:
            logger.error(f"Invalid x509 certificate chain. Parsing failed: {e}")
            return False, trust_source

        if not issuer_jwk.thumbprint == chain_jwks[-1].thumbprint:
            logger.error(f"Invalid x509 certificate chain. Issuer thumbprint does not match")
            return False, trust_source
        
        trust_source.add_trust_param(
            "x509",
            TrustEvaluationType(
                attribute_name="x5c",
                x5c=x5c,
                expiration_date=get_expiry_date_from_x5c(chain),
                jwks=chain_jwks,
                trust_handler_name=self.name,
            )
        )

        return True, trust_source
    
    def get_handled_trust_material_name(self) -> str:
        return "x5c"
    
    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        return trust_source
