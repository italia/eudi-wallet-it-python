import binascii
import json
import logging
from typing import Union

import cryptojwt
from cryptojwt.jwe.jwe import factory
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA

from pyeudiw.jwt.exceptions import JWEDecryptionError, JWEEncryptionError
from pyeudiw.jwt.helper import JWHelperInterface
from pyeudiw.jwt.jws_helper import DEFAULT_ENC_ALG_MAP, DEFAULT_ENC_ENC_MAP
from pyeudiw.jwt.utils import decode_jwt_header

logger = logging.getLogger(__name__)


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
        if isinstance(plain_dict, dict):
            _payload = json.dumps(plain_dict).encode()
        elif not plain_dict:
            _payload = ""
        elif isinstance(plain_dict, (str, int)):
            _payload = plain_dict
        else:
            _payload = ""

        encryption_keys = [key for key in self.jwks if key.appropriate_for("encrypt")]

        if len(encryption_keys) == 0:
            raise JWEEncryptionError(
                "unable to produce JWE: no available encryption key(s)"
            )

        for key in self.jwks:
            if isinstance(key, cryptojwt.jwk.rsa.RSAKey):
                JWE_CLASS = JWE_RSA
            elif isinstance(key, cryptojwt.jwk.ec.ECKey):
                JWE_CLASS = JWE_EC
            else:
                # unsupported key: go to next one
                continue

            _keyobj = JWE_CLASS(
                _payload,
                alg=DEFAULT_ENC_ALG_MAP[key.kty],
                enc=DEFAULT_ENC_ENC_MAP[key.kty],
                kid=key.kid,
                **kwargs,
            )

            if key.kty == "EC":
                _keyobj: JWE_EC
                cek, encrypted_key, iv, params = _keyobj.enc_setup(
                    msg=_payload, key=key
                )
                kwargs = {
                    "params": params,
                    "cek": cek,
                    "iv": iv,
                    "encrypted_key": encrypted_key,
                }
                return _keyobj.encrypt(**kwargs)
            else:
                return _keyobj.encrypt(key=key.public_key())

        raise JWEEncryptionError(
            "unable to produce JWE: no supported encryption key(s)"
        )

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
                f"Not a valid JWE format for the following reason: {e}"
            )

        _alg = jwe_header.get("alg")
        _enc = jwe_header.get("enc")
        _kid = jwe_header.get("kid")
        _jwk = self.get_jwk_by_kid(_kid)

        _decryptor = factory(jwe, alg=_alg, enc=_enc)

        if isinstance(_jwk, cryptojwt.jwk.ec.ECKey):
            jwdec = JWE_EC()
            jwdec.dec_setup(_decryptor.jwt, key=_jwk.private_key())
            msg = jwdec.decrypt(_decryptor.jwt)
        else:
            msg = _decryptor.decrypt(jwe, [_jwk])

        try:
            msg_dict = json.loads(msg)
        except json.decoder.JSONDecodeError:
            msg_dict = msg
        return msg_dict
