import binascii
import json
from typing import Union, Any

import cryptojwt
from cryptojwt.jwe.jwe import factory
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS as JWSec


from pyeudiw.jwk.exceptions import KidError
from pyeudiw.jwt.utils import decode_jwt_header
from pyeudiw.jwt.exceptions import JWEEncryptionError

from .exceptions import JWEDecryptionError, JWSVerificationError

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.okp import OKPKey
from cryptojwt.jwk.hmac import SYMKey

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


class JWHelperInterface:
    def __init__(self, jwk: ECKey | RSAKey | OKPKey | SYMKey | dict):
        """
        Creates an instance of JWEHelper.

        :param jwk: The JWK used to crypt and encrypt the content of JWE.
        :type jwk: JWK
        """
        self.jwk = jwk
        if isinstance(jwk, dict):
            self.jwk = key_from_jwk_dict(jwk)
        self.alg = self.jwk.alg or DEFAULT_SIG_ALG_MAP[self.jwk.kty]


class JWEHelper(JWHelperInterface):
    """
    The helper class for work with JWEs.
    """

    def encrypt(self, plain_dict: Union[dict, str, int, None], **kwargs) -> str:
        """
        Generate a encrypted JWE string.

        :param plain_dict: The payload of JWE.
        :type plain_dict: Union[dict, str, int, None]
        :param kwargs: Other optional fields to generate the JWE.

        :returns: A string that represents the JWE.
        :rtype: str
        """

        if isinstance(self.jwk, cryptojwt.jwk.rsa.RSAKey):
            JWE_CLASS = JWE_RSA
        elif isinstance(self.jwk, cryptojwt.jwk.ec.ECKey):
            JWE_CLASS = JWE_EC
        else:
            raise JWEEncryptionError(
                f"Error while encrypting: f{self.jwk.__class__.__name__} not supported!")

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
            alg=DEFAULT_ENC_ALG_MAP[self.jwk.kty],
            enc=DEFAULT_ENC_ENC_MAP[self.jwk.kty],
            kid=self.jwk.kid,
            **kwargs
        )

        if self.jwk.kty == 'EC':
            _keyobj: JWE_EC
            cek, encrypted_key, iv, params, epk = _keyobj.enc_setup(
                msg=_payload, key=self.jwk)
            kwargs = {"params": params, "cek": cek,
                      "iv": iv, "encrypted_key": encrypted_key}
            return _keyobj.encrypt(**kwargs)
        else:
            return _keyobj.encrypt(key=self.jwk.public_key())

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
            raise JWEDecryptionError(
                f"Not a valid JWE format for the following reason: {e}")

        _alg = jwe_header.get("alg")
        _enc = jwe_header.get("enc")
        jwe_header.get("kid")

        _decryptor = factory(jwe, alg=_alg, enc=_enc)

        if isinstance(self.jwk, cryptojwt.jwk.ec.ECKey):
            jwdec = JWE_EC()
            jwdec.dec_setup(_decryptor.jwt, key=self.jwk.private_key())
            msg = jwdec.decrypt(_decryptor.jwt)
        else:
            msg = _decryptor.decrypt(jwe, [self.jwk])

        try:
            msg_dict = json.loads(msg)
        except json.decoder.JSONDecodeError:
            msg_dict = msg
        return msg_dict


class JWSHelper(JWHelperInterface):
    """
    The helper class for work with JWEs.
    """

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

        return _signer.sign_compact([self.jwk], protected=protected, **kwargs)

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
        _jwk_dict = self.jwk.to_dict()

        try:
            _head = decode_jwt_header(jws)
        except (binascii.Error, Exception) as e:
            raise JWSVerificationError(
                f"Not a valid JWS format for the following reason: {e}")

        if _head.get("kid"):
            if _head["kid"] != _jwk_dict["kid"]:  # pragma: no cover
                raise KidError(
                    f"{_head.get('kid')} != {_jwk_dict['kid']}. Loaded/expected is {_jwk_dict}) while the verified JWS header is {_head}"
                )
        # TODO: check why unfortunately obtaining a public key from a TEE may dump a different y value using EC keys

        verifier = JWSec(alg=self.alg, **kwargs)
        msg = verifier.verify_compact(jws, [self.jwk])
        return msg

