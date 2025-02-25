from cryptojwt.jwk.rsa import RSAKey, import_rsa_key

from pyeudiw.jwk import JWK


def parse_key_from_x5c(x5c: list[str]) -> JWK:
    """Parse a key from an x509 chain. This function currently
    support only the parsing of public RSA key from such a chain.
    The first element of the chain will contain the verifying key.
    See RFC7517 https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
    """
    public_key = import_rsa_key(x5c[0])
    key_dict = RSAKey(pub_key=public_key).to_dict()
    return JWK(key_dict)
