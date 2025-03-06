from cryptojwt.jwk.ec import import_ec_key, ECKey
from cryptojwt.jwk.rsa import RSAKey, import_rsa_key

from pyeudiw.jwk import JWK
from pyeudiw.jwk.exceptions import InvalidJwk
from typing import Optional

def _parse_rsa_key(x5c: list[str]) -> Optional[JWK]:
    try:
        public_key = import_rsa_key(x5c[0])
        key_dict = RSAKey(pub_key=public_key).to_dict()
        return JWK(key_dict)
    except Exception:
        return None
    
def _parse_ec_key(x5c: list[str]) -> Optional[JWK]:
    try:
        public_key = import_ec_key(x5c[0])
        key_dict = ECKey(pub_key=public_key).to_dict()
        return JWK(key_dict)
    except Exception:
        return None


def parse_key_from_x5c(x5c: list[str]) -> JWK:
    """
    Parse a key from an x509 chain. This function currently
    support only the parsing of public RSA key from such a chain.
    The first element of the chain will contain the verifying key.
    See RFC7517 https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
    
    :param x5c: list of x509 certificates
    :type x5c: list[str]

    :raises InvalidJwk: if the key cannot be parsed from the x5c chain

    :return: JWK object
    :rtype: JWK
    """

    parsing_funcs = [_parse_rsa_key, _parse_ec_key]

    for func in parsing_funcs:
        key = func(x5c)
        if key:
            return key
        
    raise InvalidJwk(f"unable to parse key from x5c: {x5c}")