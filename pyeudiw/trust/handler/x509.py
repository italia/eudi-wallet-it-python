import logging
from typing import Union

from pyeudiw.x509.crl_helper import CRLHelper
from pyeudiw.x509.exceptions import CRLReadError, CRLParseError
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustEvaluationType
from pyeudiw.trust.handler.exceptions import InvalidTrustHandlerConfiguration
from pyeudiw.jwk.parse import parse_x5c_keys, parse_certificate
from cryptojwt.jwk.jwk import key_from_jwk_dict
from pyeudiw.tools.utils import timestamp_from_datetime
from pyeudiw.x509.verify import (
    PEM_cert_to_B64DER_cert,
    to_DER_cert,
    verify_x509_attestation_chain, 
    get_expiry_date_from_x5c, 
    to_pem_list, 
    to_der_list, 
    get_x509_info,
    get_trust_anchor_from_x5c,
    get_certificate_type
)

logger = logging.getLogger(__name__)


class X509Handler(TrustHandlerInterface):
    """
    X509Handler is a trust handler implementation that extracts trust material from x509 certificates.
    """

    _TRUST_TYPE = "x509"
    _TRUST_PARAMETER_NAME = "x5c"

    def __init__(
        self, 
        client_id: str, 
        leaf_certificate_chains_by_ca: dict[str, Union[list[bytes], list[str]]],
        private_keys: list[dict[str, str]],
        certificate_authorities: dict[str, Union[bytes, str]] = {},
        include_issued_jwt_header_param: bool = False,
        **kwargs
    ) -> None:        
        self.client_id = client_id
        self.certificate_authorities = certificate_authorities
        self.include_issued_jwt_header_param = include_issued_jwt_header_param

        if not leaf_certificate_chains_by_ca:
            raise InvalidTrustHandlerConfiguration("No x509 certificate chains provided in the configuration")

        self.leaf_certificate_chains_by_ca = {}

        private_keys_thumbprints = [key_from_jwk_dict(key, private=False).thumbprint("SHA-256") for key in private_keys]
        certificate_authorities_thumbprint = [parse_certificate(ca).thumbprint for ca in certificate_authorities.values()]

        has_a_valid_chain = False

        for k, v in leaf_certificate_chains_by_ca.items():
            root_dns_name = get_x509_info(v[-1])
            
            if not root_dns_name in k:
                raise InvalidTrustHandlerConfiguration(f"Invalid x509 certificate: expected {k} got {root_dns_name} instead of {k}")
            
            root_cert_thumbprint = parse_certificate(v[-1]).thumbprint

            if not root_cert_thumbprint in certificate_authorities_thumbprint:
                logger.error(f"Invalid x509 leaf certificate using CA {k}. Unmatching root certificate, the chain will be removed")
                continue

            found_client_id = False

            client_id_dns = self.client_id.split(":")[-1].split("://")[-1].split("/")[0]

            for cert in v[:-1]:
                if get_x509_info(cert) == client_id_dns:
                    found_client_id = True
                    break
                
            if not found_client_id:
                logger.error(f"Invalid x509 leaf certificate using CA {k}. Unmatching client id ({client_id}); the chain will be removed")
                continue

            pem_type = get_certificate_type(v[0])

            if not pem_type in private_keys[0]["kty"]:
                raise InvalidTrustHandlerConfiguration(
                    f"Invalid x509 certificate: expected algorithm for metadata key 0 {private_keys[0]['kty'][:2]} got {pem_type}"
                )

            relative_to_rp = False

            for cert in v[:-1]:
                cert_jwk = parse_certificate(cert)
                if cert_jwk.thumbprint == private_keys_thumbprints[0]:
                    relative_to_rp = True
                    break

            if not relative_to_rp:
                logger.error(f"Invalid x509 leaf certificate using CA {k}. Unmatching private key, the chain will be removed")
                continue

            chain = to_der_list(v)

            if verify_x509_attestation_chain(chain):
                self.leaf_certificate_chains_by_ca[k] = chain
            else:
                logger.error(f"Invalid x509 certificate chain using CA {k}. Chain validation failed, the chain will be removed")
                continue         

            has_a_valid_chain = True   

        if not has_a_valid_chain:
            raise InvalidTrustHandlerConfiguration(
                f"No valid x509 certificate chains found in the configuration for client {self.client_id}. "
            )
        
        self.private_keys = private_keys

    def _verify_chain(self, x5c: list[str], crls: list[CRLHelper]) -> bool:
        """
        Verify the x5c chain.
        :param x5c: The x5c chain to verify.
        :type x5c: list[str]

        :return: True if the chain is valid, False otherwise.
        """
        der_chain = [to_DER_cert(cert) for cert in x5c]

        if len(der_chain) > 1 and not verify_x509_attestation_chain(der_chain, crls):
            logger.error(f"Invalid x509 certificate chain. Chain validation failed")
            return False

        issuer = get_trust_anchor_from_x5c(der_chain)

        if not issuer:
            logger.error("Invalid x509 certificate chain. Issuer not found")
            return False
        
        if not issuer in self.certificate_authorities:
            logger.error("Invalid x509 certificate chain. Issuer not found in the list of trusted CAs")
            return False
        
        issuer_cert = self.certificate_authorities[issuer]

        try:
            issuer_jwk = parse_certificate(issuer_cert)
            chain_jwks = parse_x5c_keys(der_chain)
        except Exception as e:
            logger.error(f"Invalid x509 certificate chain. Parsing failed: {e}")
            return False

        if not issuer_jwk.thumbprint == chain_jwks[-1].thumbprint:
            logger.error("Invalid x509 certificate chain. Issuer thumbprint does not match")
            return False
        
        return True

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        # Return the first valid chain
        if issuer.split("://")[-1].split("/")[0] == self.client_id.split(":", 1)[-1]:
            for ca, chain in self.leaf_certificate_chains_by_ca.items():
                crls = self._extract_crls(trust_source, chain)

                if not self._verify_chain(chain, crls):
                    logger.error(f"Invalid x509 certificate chain using CA {ca}. Chain will be ignored")
                    continue
                
                exp = get_expiry_date_from_x5c(chain)

                trust_source.add_trust_param(
                    X509Handler._TRUST_TYPE,
                    TrustEvaluationType(
                        attribute_name="x5c",
                        x5c=to_pem_list(chain),
                        expiration_date=timestamp_from_datetime(exp),
                        jwks=self.private_keys,
                        trust_handler_name=self.name,
                        crls=[crl.serialize() for crl in crls]
                    )
                )

                return trust_source
            
        return trust_source
    
    def validate_trust_material(
        self,
        chain: list[str],
        trust_source: TrustSourceData,
    ) -> tuple[bool, TrustSourceData]:
        chain_jwks = parse_x5c_keys(chain)

        crls = self._extract_crls(trust_source, chain)
        valid = self._verify_chain(chain, crls)

        if not valid:
            return False, trust_source
        
        exp = get_expiry_date_from_x5c(chain)

        trust_source.add_trust_param(
            "x509",
            TrustEvaluationType(
                attribute_name=self.get_handled_trust_material_name(),
                x5c=to_pem_list(chain),
                expiration_date=timestamp_from_datetime(exp),
                jwks=chain_jwks,
                trust_handler_name=self.name,
                crls=[crl.serialize() for crl in crls],
            )
        )

        return True, trust_source

    def extract_jwt_header_trust_parameters(self, trust_source: TrustSourceData) -> dict:
        tp: dict = trust_source.serialize().get(X509Handler._TRUST_TYPE, {})
        if (x5c_pem := tp.get(X509Handler._TRUST_PARAMETER_NAME, None)):
            x5c = [PEM_cert_to_B64DER_cert(pem) for pem in x5c_pem]
            return {"x5c": x5c}
        return {}
    
    def get_handled_trust_material_name(self) -> str:
        return X509Handler._TRUST_PARAMETER_NAME
    
    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        return trust_source

    @staticmethod
    def _extract_crls(trust_source: TrustSourceData, chain: list[str]) -> list[CRLHelper]:
        x509_param = trust_source.get_trust_param("x509")
        crls: list[CRLHelper] = []

        if x509_param and x509_param.crls:
            for crl in x509_param.crls:
                crl_hlper = CRLHelper.from_crl(
                    crl["pem"],
                    uri=crl["uri"],
                )

                if crl_hlper.is_crl_expired():
                    crl_hlper.update()

                crls.append(crl_hlper)
        else:
            for cert in chain:
                try:
                    crls = crls + CRLHelper.from_certificate(cert)
                except CRLParseError as e:
                    logger.error(f"Invalid x509 certificate chain. CRL parsing failed: {e}")
                    continue
                except CRLReadError as e:
                    if not "No CRL distribution points found in the certificate." in str(e):
                        logger.error(f"Invalid x509 certificate chain. CRL parsing failed: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Invalid x509 certificate chain. CRL parsing failed: {e}")
                    continue

        return crls