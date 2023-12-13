import binascii
import json
from typing import Union, Any

import cryptojwt
from cryptojwt.jwe.jwe import factory
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS as JWSec

from pyeudiw.jwk import JWK
from pyeudiw.jwk.exceptions import KidError
from pyeudiw.jwt.utils import decode_jwt_header

from .exceptions import JWEDecryptionError, JWSVerificationError

DEFAULT_HASH_FUNC = "SHA-256"

DEFAULT_SIG_KTY_MAP = {
    "RSA": "RS256",
    "EC": "ES256"
}

DEFAULT_SIG_ALG_MAP = {
    "RSA": "RS256",
    "EC": "ES256"
}

DEFAULT_ENC_ALG_MAP = {
    "RSA": "RSA-OAEP",
    "EC": "ECDH-ES+A256KW"
}

DEFAULT_ENC_ENC_MAP = {
    "RSA": "A256CBC-HS512",
    "EC": "A256GCM"
}


class JWEHelper():
    """
    The helper class for work with JWEs.
    """
    def __init__(self, jwk: Union[JWK, dict]):
        """
        Creates an instance of JWEHelper.

        :param jwk: The JWK used to crypt and encrypt the content of JWE.
        :type jwk: JWK
        """
        self.jwk = jwk
        if isinstance(jwk, dict):
            self.jwk = JWK(jwk)
        self.alg = DEFAULT_SIG_KTY_MAP[self.jwk.key.kty]

    def encrypt(self, plain_dict: Union[dict, str, int, None], **kwargs) -> str:
        """
        Generate a encrypted JWE string.

        :param plain_dict: The payload of JWE.
        :type plain_dict: Union[dict, str, int, None]
        :param kwargs: Other optional fields to generate the JWE.

        :returns: A string that represents the JWE.
        :rtype: str
        """
        _key = key_from_jwk_dict(self.jwk.as_dict())

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
            alg=DEFAULT_ENC_ALG_MAP[_key.kty],
            enc=DEFAULT_ENC_ENC_MAP[_key.kty],
            kid=_key.kid,
            **kwargs
        )

        if _key.kty == 'EC':
            # TODO - TypeError: key must be bytes-like
            return _keyobj.encrypt(cek=_key.public_key())
        else:
            return _keyobj.encrypt(key=_key.public_key())

    def decrypt(self, jwe: str) -> dict:
        """
        Generate a dict containing the content of decrypted JWE string.

        :param jwe: A string representing the jwe.
        :type jwe: str

        :raises JWEDecryptionError: if jwe field is not in a JWE Format

        :returns: A dict that represents the payload of decrypted JWE.
        :rtype: dict
        """
        try:
            jwe_header = decode_jwt_header(jwe)
        except (binascii.Error, Exception) as e:
            raise JWEDecryptionError(f"Not a valid JWE format for the following reason: {e}")

        _alg = jwe_header.get("alg")
        _enc = jwe_header.get("enc")
        jwe_header.get("kid")

        _decryptor = factory(jwe, alg=_alg, enc=_enc)

        _dkey = key_from_jwk_dict(self.jwk.as_dict())
        msg = _decryptor.decrypt(jwe, [_dkey])

        try:
            msg_dict = json.loads(msg)
        except json.decoder.JSONDecodeError:
            msg_dict = msg
        return msg_dict


class JWSHelper:
    """
    The helper class for work with JWEs.
    """
    def __init__(self, jwk: Union[JWK, dict]):
        """
        Creates an instance of JWSHelper.

        :param jwk: The JWK used to sign and verify the content of JWS.
        :type jwk: Union[JWK, dict]
        """
        self.jwk = jwk
        if isinstance(jwk, dict):
            self.jwk = JWK(jwk)
        self.alg = DEFAULT_SIG_KTY_MAP[self.jwk.key.kty]

    def sign(
        self,
        plain_dict: Union[dict, str, int, None],
        protected: dict = {},
        **kwargs
    ) -> str:
        """
        Generate a encrypted JWS string.

        :param plain_dict: The payload of JWS.
        :type plain_dict: Union[dict, str, int, None]
        :param protected: a dict containing all the values 
        to include in the protected header.
        :type protected: dict
        :param kwargs: Other optional fields to generate the JWE.

        :returns: A string that represents the JWS.
        :rtype: str
        """
        _key = key_from_jwk_dict(self.jwk.as_dict())

        _payload: str | int | bytes = ""

        if isinstance(plain_dict, dict):
            _payload = json.dumps(plain_dict).encode()
        elif not plain_dict:
            _payload = ""
        elif isinstance(plain_dict, (str, int)):
            _payload = plain_dict
        else:
            _payload = ""

        _signer = JWSec(_payload, alg=self.alg, **kwargs)
        return _signer.sign_compact([_key], protected=protected, **kwargs)

    def verify(self, jws: str, **kwargs) -> (str | Any | bytes):
        """
        Verify a JWS string.

        :param jws: A string representing the jwe.
        :type jws: str
        :param kwargs: Other optional fields to generate the JWE.

        :raises JWSVerificationError: if jws field is not in a JWS Format

        :returns: A string that represents the payload of JWS.
        :rtype: str
        """
        _key = key_from_jwk_dict(self.jwk.as_dict())
        _jwk_dict = self.jwk.as_dict()

        try:
            _head = decode_jwt_header(jws)
        except (binascii.Error, Exception) as e:
            raise JWSVerificationError(f"Not a valid JWS format for the following reason: {e}")

        if _head.get("kid"):
            if _head["kid"] != _jwk_dict["kid"]:  # pragma: no cover
                raise KidError(
                    f"{_head.get('kid')} != {_jwk_dict['kid']}. Loaded/expected is {_jwk_dict}) while the verified JWS header is {_head}"
                )
        # TODO: check why unfortunately obtaining a public key from a TEE may dump a different y value using EC keys
        # elif _head.get("jwk"):
            # if _head["jwk"] != _jwk_dict:  # pragma: no cover
                # raise JwkError(
                # f"{_head['jwk']} != {_jwk_dict}"
                # )

        verifier = JWSec(alg=_head["alg"], **kwargs)
        msg = verifier.verify_compact(jws, [_key])
        return msg
