import binascii
from copy import deepcopy
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
from pyeudiw.jwk.jwks import find_jwk_by_kid, find_jwk_by_thumbprint
from pyeudiw.jwt.exceptions import JWSSigningError
from pyeudiw.jwt.helper import find_self_contained_key, serialize_payload
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

KeyLike: TypeAlias = ECKey | RSAKey | OKPKey | SYMKey
SerializationFormat = Literal["compact", "json"]


logger = logging.getLogger(__name__)


class JWHelperInterface:
    def __init__(self, jwks: list[KeyLike | dict] | KeyLike | dict):
        """
        Creates an instance of JWEHelper.

        :param jwks: The list of JWK used to crypt and encrypt the content of JWE.

        """
        self.jwks: list[KeyLike] = []
        if isinstance(jwks, dict):
            single_jwk = key_from_jwk_dict(jwks)
            self.jwks = [single_jwk]
        elif isinstance(jwks, list):
            self.jwks = []
            for j in jwks:
                if isinstance(j, dict):
                    j = key_from_jwk_dict(j)
                self.jwks.append(j)
        elif isinstance(jwks, (ECKey, RSAKey, OKPKey, SYMKey)):
            self.jwks = [jwks]
        else:
            raise TypeError(f"unable to handle input jwks with type {type(jwks)}")

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
        protected: dict | None = None,
        unprotected: dict | None = None,
        serialization_format: SerializationFormat = "compact",
        with_kid: bool = True,
    ) -> str:
        """Generate a signed JWS with the given payload and header.
        This method provides no guarantee that the input header is fully preserved,
        not does it guarantee that some optional but usually found header such
        as 'typ' and 'kid' are present.
        If the signing key has a kid claim, and the JWS header does not a have a kid claim,
        a kid matching the signing key 'kid' can be injected in the protected header
        by setting with_kid=True.
        
        Header claim 'alg' is always added as it is mandated by RFC7515
        and, if present, will be overridden with the actual 'alg' used for singing.
        This is done to make sure that untrusted alg values, such as none, cannot be used.

        If the header already contains indication of a key, such as 'kid',
        'trust_chain' and 'x5c', there is no guarantee that the signing
        key to be used will be aligned with those header. We assume that is
        it responsability of the class initiator to make those checks.

        :param payload: The payload of JWS to be signed.
        :type payload: Union[dict, str, int, None]
        :param protected: a dict containing all the values to include in the signed token header.
        :type protected: dict
        :param unprotected: a dict containing all the values to include in the unsigned token header when using json serializarion.
        :param with_kid: is true, insert the siging key kid (if any) in the token header if and only if it is missing
        :type with_kid: bool

        :returns: A string that represents the signed token.
        :rtype: str

        :raises JWSSigningError: if there is any signing error, such as the signing
            key not being suitable for such a cryptographic operation
        """

        if protected is None:
            protected = {}
        if unprotected is None:
            unprotected = {}

        signing_key = self._select_signing_key((protected, unprotected))  # TODO: check that singing key is either private or symmetric
        # sanity check: signing key matches what declared in header
        header_kid = protected.get("kid")
        signer_kid = signing_key.get("kid")
        if header_kid and signer_kid and (header_kid != signer_kid):
            raise JWSSigningError(f"token header contains a kid {header_kid} that does not match the signing key kid {signer_kid}")

        payload = serialize_payload(plain_dict)
        # select a trusted alg and override header
        signing_alg: str = DEFAULT_SIG_KTY_MAP[JWK(signing_key).key.kty]
        protected["alg"] = signing_alg
        # untyped JWT are JWT...
        if "typ" not in protected:
            protected["typ"] = "JWT"
        if with_kid and signer_kid:
            protected["kid"] = signer_kid  # note that is actually redundant as the underlying library auto-update the header with the kid

        # this is a hack: if the header to be signed does NOT have kid and we do
        # not want to include it, then we must remove it from the signing kid
        # otherwise the signing library will auto insert it
        if not with_kid and not header_kid:
            signing_key = deepcopy(signing_key)
            signing_key.pop("kid", None)

        signer = JWS(payload, alg=signing_alg)
        if serialization_format == "compact":
            try:
                signed = signer.sign_compact([key_from_jwk_dict(signing_key)], protected=protected)
                return signed
            except Exception as e:
                raise JWSSigningError("signing error: error in step", e)
        if isinstance(plain_dict, bytes):
            plain_dict = plain_dict.decode()
        return signer.sign_json(keys=[key_from_jwk_dict(signing_key)], headers=[(protected, unprotected)], flatten=True)

    def _select_signing_key(self, headers: tuple[dict, dict]) -> dict:
        if len(self.jwks) == 0:
            raise JWEEncryptionError("signing error: no key available for signature; note that {'alg':'none'} is not supported")
        # Case 1: only one key
        if (signing_key := self._select_signing_key_by_uniqueness()):
            return signing_key
        # Case 2: only one *singing* key
        if (signing_key := self._select_key_by_use(use="sig")):
            return signing_key
        # Case 3: match key by kid: this goes beyond what promised on the method definition
        if (signing_key := self._select_key_by_kid(headers)):
            return signing_key
        raise JWSSigningError("signing error: not possible to uniquely determine the signing key")

    def _select_signing_key_by_uniqueness(self) -> dict | None:
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()
        return None

    def _select_key_by_use(self, use: str) -> dict | None:
        candidate_signing_keys: list[dict] = []
        for key in self.jwks:
            key_d = key.to_dict()
            if use == key_d .get("use", ""):
                candidate_signing_keys.append(key_d)
        if len(candidate_signing_keys) == 1:
            return candidate_signing_keys[0]
        return None

    def _select_key_by_kid(self, headers: tuple[dict, dict]) -> dict | None:
        if "kid" in headers[0]:
            kid = headers[0]["kid"]
        elif "kid" in headers[1]:
            kid = headers[1]["kid"]
        else:
            return None
        return find_jwk_by_kid([key.to_dict() for key in self.jwks], kid)

    def verify(self, jwt: str) -> (str | Any | bytes):
        """Verify a JWS with one of the initialized keys.
        Verification of tokens in JSON serialization format is not supported.

        :param jws: The jws to be verified
        :type jws: str

        :raises JWSVerificationError: if jws field is not in compact jws
            format or if the signature is invalid

        :returns: the decoded payload of the verified tokens.
        :rtype: str
        """

        try:
            header = decode_jwt_header(jwt)
        except (binascii.Error, Exception) as e:
            raise JWSVerificationError(
                f"Not a valid JWS format for the following reason: {e}"
            )

        verifying_key = self._select_verifying_key(header)
        if not verifying_key:
            raise JWSVerificationError(f"verififcation error: unable to find matching public key for header {header}")

        # sanity check: kid must match if present
        if (expected_kid := header.get("kid")):
            obtained_kid = verifying_key.get("kid", None)
            if obtained_kid and (obtained_kid != expected_kid):
                raise JWSVerificationError(
                    KidError(
                        "unexpected verification state: found a valid verifying key,"
                        f"but its kid {obtained_kid} does not match token header kid {expected_kid}")
                )

        verifier = JWS(alg=header["alg"])
        msg = verifier.verify_compact(jwt, [key_from_jwk_dict(verifying_key)])
        return msg

    def _select_verifying_key(self, header: dict) -> dict | None:
        available_keys = [key.to_dict() for key in self.jwks]

        # case 1: can be found by header
        if "kid" in header:
            if (verifying_key := find_jwk_by_kid(available_keys, header["kid"])):
                return verifying_key

        # case 2: the token is self contained, and the verification key matches one of the key in the whitelist
        if (self_contained_claims_key_pair := find_self_contained_key(header)):
            # check if the self contained key matches a trusted jwk
            candidate_key = self_contained_claims_key_pair[0]
            if (verifying_key := find_jwk_by_thumbprint(available_keys, candidate_key.thumbprint)):
                return verifying_key

        # case 3: if only one key and there is no header claim that can identitfy any key, than that MUST
        # be the only valid CANDIDATE key for signature verification
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()
        return None
