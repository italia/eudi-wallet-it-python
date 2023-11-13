import pem
import logging
from OpenSSL import crypto
from datetime import datetime
from ssl import DER_cert_to_PEM_cert
from cryptography.x509 import load_der_x509_certificate

LOG_ERROR = "x509 verification failed: {}"

logger = logging.getLogger(__name__)

def _verify_chain(pems: list[str]):
    try:
        store = crypto.X509Store()

        x509_certs = [crypto.load_certificate(crypto.FILETYPE_PEM, str(pem)) for pem in pems]

        for cert in x509_certs[:-1]:
            store.add_cert(cert)

        store_ctx = crypto.X509StoreContext(store, x509_certs[-1])

        store_ctx.verify_certificate()

        return True
    except Exception as e:
        logging.warning(LOG_ERROR.format(e))
        return False
    
def _check_chain_len(pems: list) -> bool:
    chain_len = len(pems)

    if chain_len < 2:
        message = f"invalid chain lenght -> minimum expected 2 found {chain_len}"
        logging.warning(LOG_ERROR.format(message))
        return False
    
    return True
    
def _check_datetime(exp: datetime | None):
    if exp == None:
        return True

    if datetime.now() > exp:
        message = f"expired chain date -> {exp}"
        logging.warning(LOG_ERROR.format(message))
        return False
    
    return True

def verify_x509_attestation_chain(x5c: list[bytes], exp: datetime | None = None) -> bool:
    if not _check_chain_len(x5c) or not _check_datetime(exp):
        return False
    
    pems = [DER_cert_to_PEM_cert(cert) for cert in x5c]

    return _verify_chain(pems)
    
def verify_x509_anchor(pem_str: str, exp: datetime | None = None) -> bool:
    if not _check_datetime(exp):
        return False

    pems = [str(cert) for cert in pem.parse(pem_str)]

    if not _check_chain_len(pems):
        return False
    
    return _verify_chain(pems)

def get_issuer_from_x5c(x5c: list[bytes]) -> str:
    cert = load_der_x509_certificate(x5c[-1])
    return cert.subject.rfc4514_string().split("=")[1]
