import logging
from OpenSSL import crypto
from datetime import datetime
from ssl import DER_cert_to_PEM_cert

LOG_ERROR = "x509 verification failed: {}"

logger = logging.getLogger(__name__)

def verify_x509_cert_chain(x509: dict[str, list[bytes] | datetime]) -> bool:
    chain_len = len(x509["x5c"])

    if chain_len < 2:
        message = f"invalid chain lenght -> minimum expected 2 found {chain_len}"
        logging.warning(LOG_ERROR.format(message))
        return False
    
    if datetime.now() > x509["exp"]:
        message = f"expired chain date -> {x509["exp"]}"
        logging.warning(LOG_ERROR.format(message))
        return False

    try:
        store = crypto.X509Store()

        pems = [DER_cert_to_PEM_cert(cert) for cert in x509["x5c"]]
        x509_certs = [crypto.load_certificate(crypto.FILETYPE_PEM, str(pem)) for pem in pems]

        for cert in x509_certs[:-1]:
            store.add_cert(cert)

        store_ctx = crypto.X509StoreContext(store, x509_certs[-1])

        store_ctx.verify_certificate()

        return True
    except Exception as e:
        logging.warning(LOG_ERROR.format(e))
        return False