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

from typing import Literal

import logging

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

KeyLike = ECKey | RSAKey | OKPKey | SYMKey
SerializationFormat = Literal["compact", "json"]


logger = logging.getLogger(__name__)


class JWHelperInterface:
    def __init__(self, jwks: list[KeyLike | dict] | KeyLike | dict):
        """
        Creates an instance of JWEHelper.

        :param jwks: The list of JWK used to crypt and encrypt the content of JWE.

        """
        if isinstance(jwks, dict):
            single_jwk = key_from_jwk_dict(jwks)
            single_jwk.add_kid()
            self.jwks = [single_jwk]
        elif isinstance(jwks, list):
            self.jwks = []
            for j in jwks:
                if isinstance(j, dict):
                    j = key_from_jwk_dict(j)
                j.add_kid()
                self.jwks.append(j)
        elif isinstance(jwks, (ECKey, RSAKey, OKPKey, SYMKey)):
            jwks.add_kid()
            self.jwks = [jwks]
        else:
            logger.warning(f"Unhandled type {type(jwks)} for jwks")
            self.jwks = []
        
    def get_jwk_by_kid(self, kid: str) -> dict | KeyLike | None:
        if not kid:
            return
        for i in self.jwks:
            if i.kid == kid:
                return i


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
        
        jwe_strings =[]
        
        if isinstance(plain_dict,dict):
            _payload = json.dumps(plain_dict).encode()
        elif not plain_dict:
            _payload = ""
        elif isinstance(plain_dict, (str, int)):
            _payload = plain_dict
        else:
            _payload = ""
            
        for key in self.jwks:
            if isinstance(key, cryptojwt.jwk.rsa.RSAKey):
                JWE_CLASS = JWE_RSA
            elif isinstance(key, cryptojwt.jwk.ec.ECKey):
                JWE_CLASS = JWE_EC
            else:
                raise JWEEncryptionError(
                    f"Error while encrypting: "
                    f"{self.jwk.__class__.__name__} not supported!"
                )

            _keyobj = JWE_CLASS(
                _payload,
                alg = DEFAULT_ENC_ALG_MAP[key.kty],
                enc = DEFAULT_ENC_ENC_MAP[key.kty],
                kid = key.kid,
                **kwargs
            )

            if key.kty == 'EC':
                _keyobj: JWE_EC
                cek, encrypted_key, iv, params, epk = _keyobj.enc_setup(
                    msg=_payload,
                    key=key
                )
                kwargs = {
                    "params": params,
                    "cek": cek,
                    "iv": iv,
                    "encrypted_key": encrypted_key
                }
                return _keyobj.encrypt(**kwargs)
            else:
                return _keyobj.encrypt(
                    key=key.public_key()
                )

        return jwe_strings[0] if len(jwe_strings)==1 else jwe_strings

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


class JWSHelper(JWHelperInterface):
    """
    The helper class for work with JWEs.
    """

    def sign(
        self,
        plain_dict: Union[dict, str, int, None],
        protected: dict = {},
        unprotected: dict = {},
        serialization_format: SerializationFormat = "compact",
        kid: str = "",
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

        _payload: str | int | bytes = plain_dict
        _jwk = self.get_jwk_by_kid(kid) or self.jwks[0]
        
        if isinstance(plain_dict, dict):
            _payload = json.dumps(plain_dict)
        elif isinstance(plain_dict, (str, int)):
            _payload = plain_dict
        else:
            _payload = ""

        _alg = DEFAULT_SIG_KTY_MAP[_jwk.kty]
        _signer = JWSec(_payload, kty = _jwk.kty, alg=_alg, **kwargs)

        if serialization_format=='compact':
            return _signer.sign_compact(self.jwks, protected=protected)
        else:
            if isinstance(plain_dict, bytes):
                plain_dict = plain_dict.decode()
            return _signer.sign_json(keys=self.jwks, headers= [(protected, unprotected)], flatten=True)

    def verify(self, jwt: str, **kwargs) -> (str | Any | bytes):
        """
        Verify a JWT string.

        :param jwt: A string representing the jwe.
        :type jwt: str
        :param kwargs: Other optional fields to generate the signed JWT.

        :raises JWSVerificationError: if jws field is not in a JWT format

        :returns: A string that represents the payload of JWT.
        :rtype: str
        """
        
        try:
            _head = decode_jwt_header(jwt)
        except (binascii.Error, Exception) as e:
            raise JWSVerificationError(
                f"Not a valid JWS format for the following reason: {e}"
            )

        _jwk_dict = {}
        _jwk = None

        if _head.get("kid"):
            _jwk = self.get_jwk_by_kid(_head.get("kid"))
            if _jwk:
                _jwk_dict = _jwk.to_dict()

        if not _jwk:        
            if _head.get("x5c"):
                raise NotImplementedError(
                    f"{_head} "
                    f"contains x5c while x5c signature validation in jwt package is not implemented yet"
                )
            elif _head.get("jwk"):
                raise NotImplementedError(
                    f"{_head.get('jwk')} != {_jwk_dict}. Loaded/expected is {_jwk_dict}) while the verified JWT header is {_head}"
                )
            else:
                raise KidError(
                    f"{_head.get('kid')} != {_jwk_dict['kid']}. "
                    f"Loaded/expected is {_jwk_dict}) while the verified JWS header is {_head}"
                )
        

        verifier = JWSec(alg=_head.get("alg"), **kwargs)
        msg = verifier.verify_compact(jwt, self.jwks)
        return msg