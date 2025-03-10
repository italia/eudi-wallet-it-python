import logging
from datetime import datetime
from ssl import DER_cert_to_PEM_cert, PEM_cert_to_DER_cert

import pem
from cryptography.x509 import load_der_x509_certificate
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from OpenSSL import crypto

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

        for cert in x509_certs[:-1]:
            store.add_cert(cert)

        store_ctx = crypto.X509StoreContext(store, x509_certs[-1])
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

def to_pems_list(cert: str) -> list[str]:
    """
    Convert the x509 certificate chain from PEM to multiple PEMs.

    :param der: The x509 certificate chain in PEM format
    :type der: str

    :returns: The x509 certificate chain in PEM format
    :rtype: list[str]
    """
    return [str(cert) for cert in pem.parse(cert)]

def get_expiry_date_from_x5c(x5c: list[bytes]) -> datetime:
    """
    Get the expiry date from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The expiry date
    :rtype: datetime
    """
    cert = load_der_x509_certificate(x5c[-1])
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

    pems = to_pems_list(pem_str)

    if not _check_chain_len(pems):
        logging.error(LOG_ERROR.format("check chain len failed"))
        return False

    return _verify_x509_certificate_chain(pems)


def get_issuer_from_x5c(x5c: list[bytes]) -> str:
    """
    Get the issuer from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The issuer
    :rtype: str
    """
    cert = load_der_x509_certificate(x5c[-1])
    return cert.subject.rfc4514_string().split("=")[1]

def get_expiry_date_from_x5c(x5c: list[bytes]) -> datetime:
    """
    Get the expiry date from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The expiry date
    :rtype: datetime
    """
    cert = load_der_x509_certificate(PEM_cert_to_DER_cert(x5c[-1]))
    return cert.not_valid_after

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
