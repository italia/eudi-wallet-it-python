import base64
import binascii
import json

import cryptojwt
from cryptojwt.exception import VerificationError
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwe.jwe import factory
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
            
        _payload: str | int | bytes = ""
            
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


def unpad_jwt_element(jwt: str, position: int) -> dict:
    b = jwt.split(".")[position]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data


def unpad_jwt_head(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=0)


def unpad_jwt_payload(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=1)


def decrypt_jwe(jwe: str, jwk_dict: dict) -> dict:
    try:
        jwe_header = unpad_jwt_head(jwe)
    except (binascii.Error, Exception) as e:
        raise VerificationError("The JWT is not valid")

    _alg = jwe_header.get("alg", DEFAULT_JWE_ALG)
    _enc = jwe_header.get("enc", DEFAULT_JWE_ENC)
    jwe_header.get("kid")

    _decryptor = factory(jwe, alg=_alg, enc=_enc)

    _dkey = key_from_jwk_dict(jwk_dict)
    msg = _decryptor.decrypt(jwe, [_dkey])

    try:
        msg_dict = json.loads(msg)
    except json.decoder.JSONDecodeError:
        msg_dict = msg
    return msg_dict
