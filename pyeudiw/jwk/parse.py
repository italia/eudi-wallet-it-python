import base64
from cryptojwt.jwk.ec import import_ec_key, ECKey
from cryptojwt.jwk.rsa import RSAKey, import_rsa_key
from ssl import DER_cert_to_PEM_cert

from pyeudiw.jwk import JWK
from pyeudiw.jwk.exceptions import InvalidJwk
from typing import Optional

def _parse_rsa_key(pem: str) -> Optional[JWK]:
    try:
        public_key = import_rsa_key(pem)
        key_dict = RSAKey(pub_key=public_key).to_dict()
        return JWK(key_dict)
    except Exception:
        return None
    
def _parse_ec_key(pem: str) -> Optional[JWK]:
    try:
        public_key = import_ec_key(pem)
        key_dict = ECKey(pub_key=public_key).to_dict()
        return JWK(key_dict)
    except Exception:
        return None

def parse_pem(pem: str) -> JWK:
    """
    Parse a key from a pem string. This function currently
    support only the parsing of public RSA key from a pem string.
    
    :param pem: pem string
    :type pem: str

    :raises InvalidJwk: if the key cannot be parsed from the pem string

    :return: JWK object
    :rtype: JWK
    """

    parsing_funcs = [_parse_rsa_key, _parse_ec_key]

    for func in parsing_funcs:
        key = func(pem)
        if key:
            return key
        
    raise InvalidJwk(f"unable to parse key from pem: {pem}")

def parse_certificate(cert: str | bytes) -> JWK:
    """
    Parse a key from a x509 PEM or DER certificate.
    
    :param cert: x509 certificate in PEM or DER format
    :type cert: str | bytes

    :raises InvalidJwk: if the key cannot be parsed from the certificate

    :return: JWK object
    :rtype: JWK
    """

    if type(cert) == bytes or type(cert) == str and not cert.startswith("-----BEGIN CERTIFICATE-----"):
        cert = DER_cert_to_PEM_cert(cert)

    return parse_pem(cert)


def parse_b64der(b64der: str) -> JWK:
    """
    Parse a (public) key from a Base64 encoded DER certificate.
    """
    der = base64.b64decode(b64der)
    return parse_certificate(der)


def parse_x5c_keys(x5c: list[str]) -> list[JWK]:
    """
    Parse a the keys from a x5c chain.
    The first element of the chain will contain the verifying key.
    See RFC7517 https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
    
    :param x5c: list of x509 certificates
    :type x5c: list[str]

    :raises InvalidJwk: if the key cannot be parsed from the x5c chain

    :return: JWK object
    :rtype: JWK
    """

    return [parse_pem(pem) for pem in x5c]