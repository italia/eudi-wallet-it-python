import binascii
import json
from typing import TypeAlias, Union, Any

import cryptojwt
from cryptojwt.jwe.jwe import factory
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS

from pyeudiw.jwk import JWK
from pyeudiw.jwk.exceptions import KidError
from pyeudiw.jwk.parse import adapt_key_to_JWK, parse_key_from_x5c
from pyeudiw.jwk.jwks import find_jwk_by_thumbprint
from pyeudiw.jwt.interface import JweDecrypter, JweEncrypter, JwsSigner, JwsVerifier
from pyeudiw.jwt.log import logger
from pyeudiw.jwt.utils import decode_jwt_header
from pyeudiw.jwt.exceptions import JWEEncryptionError, JWEDecryptionError, JWSSigningError, JWSVerificationError

_JWK_RPRS_FMT: TypeAlias = cryptojwt.jwk.JWK | JWK | dict

DEFAULT_HASH_FUNC = "SHA-256"

DEFAULT_SIGN_KTY_TO_ALG = {
    "RSA": "RS256",
    "EC": "ES256"
}
"""This map defines the default signing algorithm to be used for a key
with the given kty.
"""

# DEFAULT_SIG_ALG_MAP = {
#     "RSA": "RS256",
#     "EC": "ES256"
# }


DEFAULT_ENC_KTY_TO_ALG = {
    "RSA": "RSA-OAEP",
    "EC": "ECDH-ES+A256KW"
}
"""Map of default content encryption *key* algorithms to be used when
hybrid encryption schemes (sometimes also called key encapsulation mechanism)
are used.
In parituclar, this map defines the default a-symmetric algorithm to be
used to encrypt the symmetric key that will actually encrypt the data.
"""

DEFAULT_ENC_KTY_TO_ENC = {
    "RSA": "A256CBC-HS512",
    "EC": "A256GCM"
}
"""Map of default content encryption algorithms to be used when hybrid
encryption schemes (sometimes also called key ancapsulation mechanism)
are used.
In particular, this map defines the default symmetric AEAD algorithm
for the content encryption portion of the hybrid encryption scheme.
"""


def serialize_payload(payload: dict | str | int | None) -> bytes | str | int:
    if isinstance(payload, dict):
        return json.dumps(payload).encode()
    if not payload:
        return ""
    if isinstance(payload, (str, int)):
        return payload
    return ""


class JWEHelper(JweEncrypter, JweDecrypter):
    """The helper class for work with JWEs. The purpose of this class is to
    encypt or decrypt jwe with given keys.
    """

    def __init__(self, jwk: _JWK_RPRS_FMT):
        """
        Creates an instance of JWEHelper.

        :param jwk: The JWK used to crypt and encrypt the content of JWE.
        :type jwk: JWK
        """
        self.jwk = adapt_key_to_JWK(jwk)
        self.alg = DEFAULT_ENC_KTY_TO_ALG[self.jwk.key.kty]

    def encrypt(self, payload: Union[dict, str, int, None], **kwargs) -> str:
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
        else:
            raise JWEEncryptionError(
                f"Error while encrypting: f{_key.__class__.__name__} not supported!")

        _payload: str | int | bytes = ""

        if isinstance(payload, dict):
            _payload = json.dumps(payload).encode()
        elif not payload:
            _payload = ""
        elif isinstance(payload, (str, int)):
            _payload = payload
        else:
            _payload = ""

        _keyobj = JWE_CLASS(
            _payload,
            alg=DEFAULT_ENC_KTY_TO_ALG[_key.kty],
            enc=DEFAULT_ENC_KTY_TO_ENC[_key.kty],
            kid=_key.kid,
            **kwargs
        )

        if _key.kty == 'EC':
            _keyobj: JWE_EC
            cek, encrypted_key, iv, params, epk = _keyobj.enc_setup(
                msg=_payload, key=_key)
            kwargs = {"params": params, "cek": cek,
                      "iv": iv, "encrypted_key": encrypted_key}
            return _keyobj.encrypt(**kwargs)
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
            raise JWEDecryptionError(
                f"Not a valid JWE format for the following reason: {e}")

        _alg = jwe_header.get("alg")
        _enc = jwe_header.get("enc")
        jwe_header.get("kid")

        _decryptor = factory(jwe, alg=_alg, enc=_enc)

        _dkey = key_from_jwk_dict(self.jwk.as_dict())

        if isinstance(_dkey, cryptojwt.jwk.ec.ECKey):
            jwdec = JWE_EC()
            jwdec.dec_setup(_decryptor.jwt, key=self.jwk.key.private_key())
            msg = jwdec.decrypt(_decryptor.jwt)
        else:
            msg = _decryptor.decrypt(jwe, [_dkey])

        try:
            msg_dict = json.loads(msg)
        except json.decoder.JSONDecodeError:
            msg_dict = msg
        return msg_dict


class JWSHelper(JwsSigner, JwsVerifier):
    """JWSHelper can provide utility methods to signing or verifying JWTs with
    some keys to be trusted.
    In case of signing, to avoid any ambiguity on which key to be used, it
    is suggested to instantiate the class with only one private or symmetric key.
    Multiple keys can be instantiated if and only if only one them has claim
    {'use':'sig'}, which then will be selected for signing.

    In case of verification, a set of keys can be used in the class initialization
    and they are assumed to be the trusted set of keys among which you can verify
    the token.
    The verification algorithm algorithm will then determine which key to use
    based on the header of the token to be verified.
    """

    def __init__(self, jwks: list[_JWK_RPRS_FMT] | _JWK_RPRS_FMT):
        """
        Creates an instance of JWSHelper.

        :param jwk: The JWK used to sign and verify the content of JWS.
        :type jwk: Union[JWK, dict]
        """
        self.jwks: list[JWK] = []
        if isinstance(jwks, _JWK_RPRS_FMT):
            jwks: list[_JWK_RPRS_FMT] = [jwks]
        for key in jwks:
            self.jwks.append(adapt_key_to_JWK(key))

    def sign(
        self,
        payload: Union[dict, str, int, None],
        header: dict | None = None,
        **kwargs
    ) -> str:
        """Generate a signed JWS with the given payload and header.
        This method provides no guarantee that the input header is fully preserved,
        not does it guarantee that some optional but usually found header such
        as 'typ' and 'kid' are present.
        Moreover, header claim 'alg' is always added as it is mandated by RFC7515
        and, if present, will be overridden with the actual 'alg' used for singing.
        This is done to make sure that untrusted alg values, such as none, cannot be used.

        If the header already contains indication of a key, such as 'kid',
        'trust_chain' and 'x5c', there is no guarantee that the signing
        key to be used will be aligned with those header. We assume that is
        it responsability of the class initiator to make those checks.

        :param payload: The payload of JWS to be signed.
        :type payload: Union[dict, str, int, None]
        :param header: a dict containing all the values to include in the
            protected header.
        :type header: dict
        :param kwargs: Other optional fields to generate the JWS.

        :returns: A string that represents the JWS.
        :rtype: str

        :raises JWSSigningError: if there is any signing error, such as the signing
            key not being suitable for such a cryptographic operation
        """
        if header is None:
            header = {}

        signing_key = self._select_signing_key(header)  # TODO: check that singing key is either private or symmetric
        serialized_payload = serialize_payload(payload)
        # select a trusted alg and override header
        signing_alg: str = DEFAULT_SIGN_KTY_TO_ALG[signing_key.key.kty]
        header["alg"] = signing_alg
        # untyped JWT are JWT...
        if "typ" not in header:
            header["typ"] = "JWT"

        signer = JWS(serialized_payload, alg=signing_alg, **kwargs)
        try:
            return signer.sign_compact([key_from_jwk_dict(signing_key.as_dict())], protected=header, **kwargs)
        except Exception as e:
            raise JWSSigningError("signing error: error in step", e)

    def _select_signing_key_by_uniqueness(self) -> JWK | None:
        if len(self.jwks) == 1:
            return self.jwks[0]
        return None

    def _select_key_by_use(self, use: str) -> JWK | None:
        candidate_signing_keys: list[JWK] = []
        for key in self.jwks:
            if use == key.as_dict().get("use", ""):
                candidate_signing_keys.append(key)
        if len(candidate_signing_keys) == 1:
            return candidate_signing_keys[0]
        return None

    def _select_key_by_kid(self, header: dict) -> JWK | None:
        if "kid" in header:
            kid = header["kid"]
            for key in self.jwks:
                if kid == key.as_dict().get("kid", ""):
                    return key
        return None

    def _select_signing_key(self, header: dict) -> JWK:
        if len(self.jwks) == 0:
            raise JWEEncryptionError("signing error: no key available for signature; note that {'alg':'none'} is not supported")
        # Case 1: only one key
        if (signing_key := self._select_signing_key_by_uniqueness()):
            return signing_key
        # Case 2: only one *singing* key
        if (signing_key := self._select_key_by_use(use="sig")):
            return signing_key
        # Case 3: match key by kid: this goes beyond what promised on the method definition
        if (signing_key := self._select_key_by_kid(header)):
            return signing_key
        raise JWSSigningError("signing error: not possible to uniquely determine the signing key")

    def verify(self, jws: str) -> (str | Any | bytes):
        """Verify a JWS with one of the initialized keys.

        :param jws: The jws to be verified
        :type jws: str

        :raises JWSVerificationError: if jws field is not in compact jws
            format or if the signature is invalid

        :returns: A string that represents the payload of JWS.
        :rtype: str
        """
        try:
            header = decode_jwt_header(jws)
        except (binascii.Error, Exception) as e:
            raise JWSVerificationError(
                f"verification error: not a valid JWS format for the following reason: {e}")
        verifying_key = self._select_verifying_key(header)
        if not verifying_key:
            raise JWSVerificationError(f"verififcation error: unable to find matching public key for header {header}")

        if (expected_kid := header.get("kid")):
            obtained_kid = verifying_key.as_dict().get("kid")
            if obtained_kid and (obtained_kid != expected_kid):
                raise JWSVerificationError(
                    KidError(
                        "unexpected verification state: found a valid verifying key,"
                        f"but its kid {obtained_kid} does not match token header kid {expected_kid}")
                )

        # TODO: check why unfortunately obtaining a public key from a TEE may dump a different y value using EC keys
        # elif _head.get("jwk"):
        #     if _head["jwk"] != _jwk_dict:  # pragma: no cover
        #         raise JwkError(
        #         f"{_head['jwk']} != {_jwk_dict}"
        #         )

        verifier = JWS(alg=header["alg"])

        try:
            return verifier.verify_compact(jws, [key_from_jwk_dict(verifying_key.as_dict())])
        except Exception as e:
            raise JWSVerificationError("verification error: invalid key or signature", e)

    def _select_verifying_key(self, header: dict) -> JWK | None:
        if "kid" in header:
            if (verifying_key := self._select_key_by_kid(header)):
                return verifying_key
        # TODO: refactor things below in a method with signature 'find_self_contained_key(token_header: str) -> JWK | None'
        # to be defined in the jwk.parse package
        if "x5c" in header:
            candidate_key: JWK | None = None
            try:
                candidate_key = parse_key_from_x5c(header["x5c"])
            except Exception as e:
                logger.debug(f"failed to parse key from x5c chain {header['x5c']}", exc_info=e)
            if candidate_key:
                if (verifying_key := find_jwk_by_thumbprint(self.jwks, candidate_key.thumbprint)):
                    return verifying_key
        if "jwk" in header:
            candidate_key = JWK(header["jwk"])
            if (verifying_key := find_jwk_by_thumbprint(self.jwks, candidate_key.thumbprint)):
                return verifying_key
        unsupported_claims = set(("trust_chain", "jku", "x5u", "x5t"))
        if unsupported_claims.intersection(header):
            raise JWSVerificationError(NotImplementedError(f"self contained key extraction form header with claims {unsupported_claims} not supported yet"))
        # if only one key and there is no header claim that can identitfy any key, than that MUST
        # be the only valid candidate key for signature verification
        if len(self.jwks) == 1:
            return self.jwks[0]
        return None
