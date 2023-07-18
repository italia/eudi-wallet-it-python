import base64
import binascii
import json

import cryptojwt
from cryptojwt.exception import VerificationError
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jws.utils import left_hash
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwe.jwe import factory
from cryptojwt.jws.jws import JWS as JWSec
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


def unpad_jwt_header(jwt: str) -> dict:
    b = jwt.split(".")[0]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data


def decrypt_jwe(jwe: str, jwk_dict: dict) -> dict:
    try:
        jwe_header = unpad_jwt_header(jwe)
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

class JWS():
    def __init__(self, jwk: JWK, plain_dict: Union[dict, str, int, None], alg: str = "RS256", protected: dict = {}, **kwargs):
        _key = key_from_jwk_dict(jwk.as_dict())
        
        _payload: str | int | bytes = ""
            
        if isinstance(plain_dict, dict):
            _payload = json.dumps(plain_dict).encode()
        elif not plain_dict:
            _payload = ""
        elif isinstance(plain_dict, (str, int)):
            _payload = plain_dict
        else:
            _payload = ""
        
        _signer = JWSec(_payload, alg=alg, **kwargs)

        self.signature = _signer.sign_compact([_key], protected=protected, **kwargs)
        
def verify_jws(jws: JWS, pub_jwk: dict, **kwargs) -> str:
    _key = key_from_jwk_dict(pub_jwk)

    _head = unpad_jwt_header(jws.signature)
    if _head.get("kid") != pub_jwk["kid"]:  # pragma: no cover
        raise Exception(
            f"kid error: {_head.get('kid')} != {pub_jwk['kid']}"
        )

    _alg = _head["alg"]

    verifier = JWSec(alg=_head["alg"], **kwargs)
    msg = verifier.verify_compact(jws, [_key])
    return msg


def verify_at_hash(id_token, access_token) -> bool:
    id_token_at_hash = id_token['at_hash']
    at_hash = left_hash(access_token, "HS256")
    if at_hash != id_token_at_hash:
        raise Exception(
            f"at_hash error: {at_hash} != {id_token_at_hash}"
        )
    return True