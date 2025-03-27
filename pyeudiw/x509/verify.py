import logging
from datetime import datetime
from ssl import DER_cert_to_PEM_cert, PEM_cert_to_DER_cert

import pem
from typing import Optional
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from OpenSSL import crypto
import re

LOG_ERROR = "x509 verification failed: {}"

logger = logging.getLogger(__name__)


def _verify_x509_certificate_chain(pems: list[str]):
    """
    Verify the x509 certificate chain.

    :param pems: The x509 certificate chain
    :type pems: list[str]

    :returns: True if the x509 certificate chain is valid else False
    :rtype: bool
    """
    try:
        store = crypto.X509Store()
        x509_certs = [
            crypto.load_certificate(crypto.FILETYPE_PEM, str(pem)) for pem in pems
        ]

        for cert in x509_certs[1:]:
            store.add_cert(cert)

        store_ctx = crypto.X509StoreContext(store, x509_certs[0])

        store_ctx.verify_certificate()
        return True
    except crypto.Error as e:
        _message = f"cert's chain result invalid for the following reason -> {e}"
        logging.warning(LOG_ERROR.format(_message))
        return False
    except Exception as e:
        _message = f"cert's chain cannot be validated for error -> {e}"
        logging.warning(LOG_ERROR.format(e))
        return False


def _check_chain_len(pems: list) -> bool:
    """
    Check the x509 certificate chain lenght.

    :param pems: The x509 certificate chain
    :type pems: list

    :returns: True if the x509 certificate chain lenght is valid else False
    :rtype: bool
    """
    chain_len = len(pems)
    if chain_len < 2:
        message = f"invalid chain lenght -> minimum expected 2 found {chain_len}"
        logging.warning(LOG_ERROR.format(message))
        return False

    return True


def _check_datetime(exp: datetime | None):
    """
    Check the x509 certificate chain expiration date.

    :param exp: The x509 certificate chain expiration date
    :type exp: datetime.datetime | None

    :returns: True if the x509 certificate chain expiration date is valid else False
    :rtype: bool
    """
    if exp is None:
        return True

    if datetime.now() > exp:
        message = f"expired chain date -> {exp}"
        logging.warning(LOG_ERROR.format(message))
        return False

    return True


def verify_x509_attestation_chain(x5c: list[bytes]) -> bool:
    """
    Verify the x509 attestation certificate chain.

    :param x5c: The x509 attestation certificate chain
    :type x5c: list[bytes]

    :returns: True if the x509 attestation certificate chain is valid else False
    :rtype: bool
    """
    exp = get_expiry_date_from_x5c(x5c)

    if not _check_chain_len(x5c) or not _check_datetime(exp):
        return False
    
    pems = [DER_cert_to_PEM_cert(cert) for cert in x5c]

    return _verify_x509_certificate_chain(pems)

def pem_to_pems_list(cert: str) -> list[str]:
    """
    Convert the x509 certificate chain from PEM to multiple PEMs.

    :param der: The x509 certificate chain in PEM format
    :type der: str

    :returns: The x509 certificate chain in PEM format
    :rtype: list[str]
    """
    return [str(cert) for cert in pem.parse(cert)]

def der_list_to_pem_list(der_list: list[bytes]) -> list[str]:
    """
    Convert the x509 certificate chain from DER to PEM.

    :param der: The x509 certificate chain in DER format
    :type der: list[bytes]

    :returns: The x509 certificate chain in PEM format
    :rtype: list[str]
    """
    return [DER_cert_to_PEM_cert(cert) for cert in der_list]

def pem_list_to_der_list(pem_list: list[str]) -> list[bytes]:
    """
    Convert the x509 certificate chain from PEM to DER.

    :param pem_list: The x509 certificate chain in PEM format
    :type pem_list: list[str]

    :returns: The x509 certificate chain in DER format
    :rtype: list[bytes]
    """
    return [PEM_cert_to_DER_cert(cert) for cert in pem_list]

def get_expiry_date_from_x5c(x5c: list[bytes]) -> datetime:
    """
    Get the expiry date from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The expiry date
    :rtype: datetime
    """
    cert = load_der_x509_certificate(x5c[0])
    return cert.not_valid_after

def verify_x509_anchor(pem_str: str) -> bool:
    """
    Verify the x509 anchor certificate.

    :param pem_str: The x509 anchor certificate
    :type pem_str: str

    :returns: True if the x509 anchor certificate is valid else False
    :rtype: bool
    """
    cert_data = load_der_x509_certificate(PEM_cert_to_DER_cert(pem_str))

    if not _check_datetime(cert_data.not_valid_after):
        logging.error(LOG_ERROR.format("check datetime failed"))
        return False

    pems = pem_to_pems_list(pem_str)

    if not _check_chain_len(pems):
        logging.error(LOG_ERROR.format("check chain len failed"))
        return False

    return _verify_x509_certificate_chain(pems)

def get_get_subject_name(der: bytes) -> Optional[str]:
    """
    Get the subject name from the x509 certificate.

    :param der: The x509 certificate
    :type der: bytes

    :returns: The subject name
    :rtype: str
    """
    cert = load_der_x509_certificate(der)

    #get san dns name
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    if san:
        dns = san.value.get_values_for_type(x509.DNSName)
        if dns:
            return dns[0]
        
        uri = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if uri:
            return uri[0]

    # alternatively get the common name
    subject = cert.subject.rfc4514_string()
    match = re.search(r"CN=([^,]+)", subject)
    return match.group(1).replace("CN=", "").replace("\\", "") if match else None

def get_issuer_from_x5c(x5c: list[bytes] | list[str]) -> Optional[str]:
    """
    Get the issuer from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The issuer
    :rtype: str
    """
    der = x5c[0] if isinstance(x5c[0], bytes) else PEM_cert_to_DER_cert(x5c[0])
    return get_get_subject_name(der)
    

def get_trust_anchor_from_x5c(x5c: list[bytes] | list[str]) -> Optional[str]:
    """
    Get the issuer from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The issuer
    :rtype: str
    """
    der = x5c[-1] if isinstance(x5c[-1], bytes) else PEM_cert_to_DER_cert(x5c[-1])
    return get_get_subject_name(der)

def get_expiry_date_from_x5c(x5c: list[bytes] | list[str]) -> datetime:
    """
    Get the expiry date from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The expiry date
    :rtype: datetime
    """
    der = x5c[0] if isinstance(x5c[0], bytes) else PEM_cert_to_DER_cert(x5c[0])
    cert = load_der_x509_certificate(der)
    return cert.not_valid_after

def get_x509_info(cert: bytes | str, info_type: str = "x509_san_dns") -> str:
    """
    Get the x509 certificate information.

    :param cert: The x509 certificate
    :type cert: bytes | str
    :param info_type: The information type
    :type info_type: str

    :returns: The certificate information
    :rtype: str
    """
    get_common_name = lambda cert: cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    der = cert if isinstance(cert, bytes) else PEM_cert_to_DER_cert(cert)
    cert: x509.Certificate = load_der_x509_certificate(der, default_backend())

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if info_type == "x509_san_dns":
            return san.value.get_values_for_type(x509.DNSName)[0]
        elif info_type == "x509_san_uri":
            return san.value.get_values_for_type(x509.UniformResourceIdentifier)[0]
        
        return get_common_name(cert)
    except x509.ExtensionNotFound:
        return get_common_name(cert)

def is_der_format(cert: bytes) -> str:
    """
    Check if the certificate is in DER format.

    :param cert: The certificate
    :type cert: bytes

    :returns: True if the certificate is in DER format else False
    :rtype: bool
    """
    try:
        pem = DER_cert_to_PEM_cert(cert)
        crypto.load_certificate(crypto.FILETYPE_PEM, str(pem))
        return True
    except crypto.Error as e:
        logging.error(LOG_ERROR.format(e))
        return False


def get_public_key_from_x509_chain(x5c: list[bytes]) -> ECKey | RSAKey | dict:
    raise NotImplementedError("TODO")
