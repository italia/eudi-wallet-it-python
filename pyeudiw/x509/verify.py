from OpenSSL import crypto
from datetime import datetime

def verify_x509_cert_chain(x509: dict[str, list[bytes] | datetime]) -> bool:
    if datetime.now() > x509["exp"]:
        return False

    try:
        store = crypto.X509Store()

        cert_chain = x509["x5c"]

        for cert in cert_chain[:-1]:
            store.add_cert(cert)

        store_ctx = crypto.X509StoreContext(store, cert_chain[-1])

        store_ctx.verify_certificate()

        return True
    except Exception as e:
        return False