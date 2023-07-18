import json

import cryptojwt
from cryptojwt.exception import UnsupportedAlgorithm, VerificationError
from cryptojwt.jwe.jwe import factory
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.utils import left_hash
from typing import Union

from .jwk import JWK

DEFAULT_HASH_FUNC = "SHA-256"

DEFAULT_JWS_ALG = "RS256"
DEFAULT_JWE_ALG = "RSA-OAEP"
DEFAULT_JWE_ENC = "A256CBC-HS512"

class JWE():
    def __init__(self, plain_dict: Union[dict, str, int, None], jwk: JWK, **kwargs):
        _key = key_from_jwk_dict(jwk.as_dict())

        if isinstance(_key, cryptojwt.jwk.rsa.RSAKey):
            JWE_CLASS = JWE_RSA
        elif isinstance(_key, cryptojwt.jwk.ec.ECKey):
            JWE_CLASS = JWE_EC

        if isinstance(plain_dict, dict):
            _payload = json.dumps(plain_dict).encode()
        elif not plain_dict:
            _payload = ""
        elif isinstance(plain_dict, (str, int)):
            _payload = plain_dict
        else:
            _payload = ""

        _keyobj = JWE_CLASS(
            _payload,
            alg=DEFAULT_JWE_ALG,
            enc=DEFAULT_JWE_ENC,
            kid=_key.kid,
            **kwargs
        )

        self.jwe = _keyobj.encrypt(_key.public_key())


def create_jws(payload: dict, jwk_dict: dict, alg: str = "RS256", protected:dict = {}, **kwargs) -> str:
    _key = key_from_jwk_dict(jwk_dict)
    _signer = JWS(payload, alg=alg, **kwargs)

    signature = _signer.sign_compact([_key], protected=protected, **kwargs)
    return signature
