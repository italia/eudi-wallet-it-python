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
    get_certificate_type,
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
        **kwargs,
    ) -> None:
        self.client_id = client_id
        self.certificate_authorities = certificate_authorities
        self.include_issued_jwt_header_param = include_issued_jwt_header_param

        if not leaf_certificate_chains_by_ca:
            raise InvalidTrustHandlerConfiguration("No x509 certificate chains provided in the configuration")

        self.leaf_certificate_chains_by_ca = {}

        def _strip_pem(cert: Union[bytes, str]) -> Union[bytes, str]:
            if isinstance(cert, str):
                return cert.strip()
            return cert

        private_keys_thumbprints = [
            key_from_jwk_dict(priv_key, private=False).thumbprint("SHA-256") for priv_key in private_keys
        ]
        certificate_authorities_thumbprint = [
            parse_certificate(_strip_pem(ca_cert)).thumbprint for ca_cert in certificate_authorities.values()
        ]

        has_a_valid_chain = False
        client_id_dns = self.client_id.split(":")[-1].split("://")[-1].split("/")[0]
        failure_reasons: list[str] = []

        for ca_key, pem_chain in leaf_certificate_chains_by_ca.items():
            pem_chain = [_strip_pem(cert_pem) for cert_pem in pem_chain]
            root_dns_name = get_x509_info(pem_chain[-1])
            if root_dns_name not in ca_key:
                raise InvalidTrustHandlerConfiguration(
                    f"Invalid x509 certificate: expected root DNS name to match key {ca_key!r} but got {root_dns_name!r}. "
                    f"Ensure the last certificate in the chain is the root CA and its SAN/CN matches the key."
                )

            root_cert_thumbprint = parse_certificate(pem_chain[-1]).thumbprint

            if root_cert_thumbprint not in certificate_authorities_thumbprint:
                reason = (
                    f"CA {ca_key!r}: root certificate thumbprint does not match any entry in certificate_authorities. "
                    "The chain's root cert must be the same as the cert in certificate_authorities for this CA."
                )
                failure_reasons.append(reason)
                logger.error("Invalid x509 leaf certificate using CA %s. Unmatching root certificate, the chain will be removed", ca_key)
                continue

            found_client_id = False
            for cert in pem_chain[:-1]:
                if get_x509_info(cert) == client_id_dns:
                    found_client_id = True
                    break

            if not found_client_id:
                try:
                    leaf_sans = [get_x509_info(cert_pem) for cert_pem in pem_chain[:-1]]
                except Exception as err:
                    leaf_sans = [f"<parse error: {err}>"]
                reason = (
                    f"CA {ca_key!r}: no certificate in the chain has SAN/CN matching client_id DNS {client_id_dns!r}. "
                    f"Leaf/intermediate SANs in chain: {leaf_sans}. "
                    f"Set client_id to x509_san_dns:<your-leaf-dns> (e.g. x509_san_dns:{client_id_dns}) or fix the leaf certificate SAN."
                )
                failure_reasons.append(reason)
                logger.error(
                    "Invalid x509 leaf certificate using CA %s. Unmatching client id (%s); the chain will be removed",
                    ca_key,
                    self.client_id,
                )
                continue

            pem_type = get_certificate_type(pem_chain[0])
            if pem_type not in private_keys[0]["kty"]:
                raise InvalidTrustHandlerConfiguration(
                    f"Invalid x509 certificate: leaf certificate key type is {pem_type!r} but metadata_jwks[0] is {private_keys[0]['kty']!r}. "
                    "The leaf certificate must use the same key type as the first key in private_keys (metadata_jwks)."
                )

            relative_to_rp = False
            for cert in pem_chain[:-1]:
                cert_jwk = parse_certificate(cert)
                if cert_jwk.thumbprint == private_keys_thumbprints[0]:
                    relative_to_rp = True
                    break

            if not relative_to_rp:
                reason = (
                    f"CA {ca_key!r}: leaf certificate public key thumbprint does not match private_keys[0] (metadata_jwks[0]). "
                    "The leaf cert must be issued for the same key as the first key in metadata_jwks. "
                    "Regenerate the chain using the key that matches metadata_jwks[0], or ensure the chain was built with that key."
                )
                failure_reasons.append(reason)
                logger.error("Invalid x509 leaf certificate using CA %s. Unmatching private key, the chain will be removed", ca_key)
                continue

            chain = to_der_list(pem_chain)
            if verify_x509_attestation_chain(chain):
                self.leaf_certificate_chains_by_ca[ca_key] = chain
            else:
                reason = (
                    f"CA {ca_key!r}: chain verification failed (signature or validity). "
                    "Check that the chain order is [leaf, intermediate, root], each cert is signed by the next, and none are expired."
                )
                failure_reasons.append(reason)
                logger.error("Invalid x509 certificate chain using CA %s. Chain validation failed, the chain will be removed", ca_key)
                continue

            has_a_valid_chain = True

        if not has_a_valid_chain:
            reasons_text = " | ".join(failure_reasons) if failure_reasons else " (no detailed reasons captured)"
            guidance = (
                "How to resolve: (1) client_id must be x509_san_dns:<dns> matching leaf SAN. "
                "(2) Leaf cert must be issued for the same key as metadata_jwks[0]; regenerate chain with that key. "
                "(3) Chain order [leaf, intermediate, root]; root must match certificate_authorities. "
                "(4) All certs valid and signed by next in chain."
            )
            raise InvalidTrustHandlerConfiguration(
                f"No valid x509 certificate chains for client {self.client_id}. "
                f"Expected leaf SAN DNS: {client_id_dns!r}. "
                f"Chains checked: {list(leaf_certificate_chains_by_ca.keys())}. Failures: {reasons_text}. "
                f"{guidance}"
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
            logger.error("Invalid x509 certificate chain. Chain validation failed")
            return False

        issuer = get_trust_anchor_from_x5c(der_chain)

        if not issuer:
            logger.error("Invalid x509 certificate chain. Issuer not found")
            return False

        if issuer not in self.certificate_authorities:
            logger.error("Invalid x509 certificate chain. Issuer not found in the list of trusted CAs")
            return False

        issuer_cert = self.certificate_authorities[issuer]

        try:
            issuer_jwk = parse_certificate(issuer_cert)
            chain_jwks = parse_x5c_keys(der_chain)
        except Exception as err:
            logger.error(f"Invalid x509 certificate chain. Parsing failed: {err}")
            return False

        if not issuer_jwk.thumbprint == chain_jwks[-1].thumbprint:
            logger.error("Invalid x509 certificate chain. Issuer thumbprint does not match")
            return False

        return True

    def extract_and_update_trust_materials(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        # Return the first valid chain
        if issuer.split("://")[-1].split("/")[0] == self.client_id.split(":", 1)[-1]:
            for ca_name, chain in self.leaf_certificate_chains_by_ca.items():
                crls = self._extract_crls(trust_source, chain)

                if not self._verify_chain(chain, crls):
                    logger.error(f"Invalid x509 certificate chain using CA {ca_name}. Chain will be ignored")
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
                        crls=[crl.serialize() for crl in crls],
                    ),
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
            ),
        )

        return True, trust_source

    def extract_jwt_header_trust_parameters(self, trust_source: TrustSourceData) -> dict:
        tp: dict = trust_source.serialize().get(X509Handler._TRUST_TYPE, {})
        if x5c_pem := tp.get(X509Handler._TRUST_PARAMETER_NAME, None):
            x5c = [PEM_cert_to_B64DER_cert(pem) for pem in x5c_pem]
            return {"x5c": x5c}
        return {}

    def get_handled_trust_material_name(self) -> str:
        return X509Handler._TRUST_PARAMETER_NAME

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
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
                except CRLParseError as err:
                    logger.error(f"Invalid x509 certificate chain. CRL parsing failed: {err}")
                    continue
                except CRLReadError as err:
                    if "No CRL distribution points found in the certificate." not in str(err):
                        logger.error(f"Invalid x509 certificate chain. CRL parsing failed: {err}")
                    continue
                except Exception as err:
                    logger.error(f"Invalid x509 certificate chain. CRL parsing failed: {err}")
                    continue

        return crls
