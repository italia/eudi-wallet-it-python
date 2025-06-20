import binascii
import logging
import os
from copy import deepcopy
from typing import Any, Literal, Union

from cryptojwt import JWS
from cryptojwt.jwk.jwk import key_from_jwk_dict

from pyeudiw.jwk import JWK
from pyeudiw.jwk.exceptions import KidError
from pyeudiw.jwk.jwks import find_jwk_by_kid, find_jwk_by_thumbprint
from pyeudiw.jwk.parse import parse_b64der
from pyeudiw.jwt.exceptions import (
    JWSSigningError,
    JWSVerificationError,
    LifetimeException,
)
from pyeudiw.jwt.helper import (
    JWHelperInterface,
    find_self_contained_key,
    serialize_payload,
    validate_jwt_timestamps_claims,
)
from pyeudiw.jwt.utils import decode_jwt_header

SerializationFormat = Literal["compact", "json"]

logger = logging.getLogger(__name__)

DEFAULT_HASH_FUNC = "SHA-256"

DEFAULT_SIG_KTY_MAP = {"RSA": "RS256", "EC": "ES256"}

DEFAULT_SIG_ALG_MAP = {"RSA": "RS256", "EC": "ES256"}

DEFAULT_ENC_ALG_MAP = {"RSA": "RSA-OAEP", "EC": "ECDH-ES+A256KW"}

DEFAULT_ENC_ENC_MAP = {"RSA": "A256CBC-HS512", "EC": "A256GCM"}

DEFAULT_TOKEN_TIME_TOLERANCE = int(
    os.getenv("PYEUDIW_TOKEN_TIME_TOLERANCE", "60"), base=10
)


class JWSHelper(JWHelperInterface):
    """
    Helper class for working with JWS, extended to support SD-JWT.
    """

    def sign(
        self,
        plain_dict: Union[dict, str, int, None],
        protected: dict | None = None,
        unprotected: dict | None = None,
        serialization_format: SerializationFormat = "compact",
        signing_kid: str = "",
        kid_in_header: bool = True,
        signing_algs: list[str] = [],
        **kwargs,
    ) -> str:
        """Generate a signed JWS with the given payload and header.
        This method provides no guarantee that the input header is fully preserved,
        not does it guarantee that some optional but usually found header such
        as 'typ' and 'kid' are present.
        If the signing jwk has a kid claim, and the JWS header does not a have a kid claim,
        a kid matching the signing key 'kid' can be injected in the protected header
        by setting kid_in_header=True.

        Header claim 'alg' is always added as it is mandated by RFC7515
        and, if present, will be overridden with the actual 'alg' used for singing.
        This is done to make sure that untrusted alg values, such as none, cannot be used.

        The signing key is selected among the constructor jwks based on internal
        heuristics. The user can force with key he can attempt to use by
        setting signing_key, which will then be looked in the internal set
        of available keys.

        If the header already contains indication of a key, such as 'kid',
        'trust_chain' and 'x5c', the method will attempt to match the signing
        key among the available keys based on such claims, but there is no
        guarantee that the correct key will be selected. We assume that is
        it responsibility of the class initiator to make those checks. To
        avoid any possible ambiguity, it is suggested to initilize the class
        with one (signing) key only.

        :param plain_dict: The payload to be signed.
        :param protected: Protected header for the JWS.
        :param unprotected: Unprotected header for the JWS (only for JSON serialization).
        :param serialization_format: The format of the signature (compact or JSON).
        :param signing_kid: The key ID for signing.
        :param kid_in_header: If True, include the key ID in the token header.
        :param kwargs: Additional parameters for the signing process.

        :returns: The signed JWS token.
        :rtype: str

        :raises JWSSigningError: if there is any signing error, such as the signing
            key not being suitable for such a cryptographic operation
        """

        if protected is None:
            protected = {}
        if unprotected is None:
            unprotected = {}

        # Select the signing key
        signing_key = self._select_signing_key((protected, unprotected), signing_kid, signing_algs)

        if signing_key["kty"] == "oct":
            raise JWSSigningError(f"Key {signing_key['kid']} is a symmetric key")

        try:
            _validate_key_with_jws_header(signing_key, protected, unprotected)
        except Exception as e:
            raise JWSSigningError(f"failed to validate signing key: it's content it not valid for current header claims: {e}", e)

        payload = serialize_payload(plain_dict)

        # Select a trusted algorithm and override header
        signing_alg: str = DEFAULT_SIG_KTY_MAP[JWK(signing_key).key.kty]
        protected["alg"] = signing_alg

        # Add "typ" header if not present
        if "typ" not in protected:
            protected["typ"] = "sd-jwt" if self.is_sd_jwt(plain_dict) else "JWT"

        # Include the signing key's kid in the header if required
        header_kid = protected.get("kid")
        signer_kid = signing_key.get("kid")
        if kid_in_header and signer_kid:
            # note that is actually redundant as the underlying library auto-update the header with the kid
            protected["kid"] = signer_kid

        # this is a hack: if the header to be signed does NOT have kid and we do
        # not want to include it, then we must remove it from the signing kid
        # otherwise the signing library will auto insert it
        if not kid_in_header and not header_kid:
            signing_key = deepcopy(signing_key)
            signing_key.pop("kid", None)

        signing_key_jwk = key_from_jwk_dict(signing_key)

        if not signing_key_jwk.priv_key:
            raise JWSSigningError(f"Key {signing_key_jwk.kid} is not a private key")

        signer = JWS(payload, alg=signing_alg)
        keys = [signing_key_jwk]

        if serialization_format == "compact":
            try:
                signed = signer.sign_compact(keys, protected=protected, **kwargs)
                return signed
            except Exception as e:
                raise JWSSigningError("Signing error: error in step", e)
        return signer.sign_json(
            keys=keys,
            headers=[(protected, unprotected)],
            flatten=True,
        )

    def _select_signing_key(
        self, 
        headers: tuple[dict, dict], 
        signing_kid: str = "",
        signing_algs: list[str] = [],
    ) -> dict:
        """
        Select a signing key based on the provided headers and optional parameters.
        This method attempts to find a suitable signing key from the initialized JWKS.

        :param headers: A tuple containing the protected and unprotected headers.
        :param signing_kid: Optional key ID to force the selection of a specific signing key.
        :param signing_algs: Optional list of algorithms to force the selection of a signing key.
        :returns: A dictionary representing the selected signing key.
        :raises JWSSigningError: If no suitable signing key is found or if the key cannot be used for signing.
        """
        if len(self.jwks) == 0:
            raise JWSSigningError(
                "signing error: no key available for signature; note that {'alg':'none'} is not supported"
            )
        # Case 1: key forced by the user
        if signing_kid:
            signing_key = self.get_jwk_by_kid(signing_kid)
            if not signing_key:
                raise JWSSigningError(
                    f"signing forced by using key with {signing_kid=}, but no such key is available"
                )
            return signing_key.to_dict()
        
        # Case 2: key forced by the user by a list of alg
        if len(signing_algs) > 0:
            signing_key: dict | None = None
            for alg in signing_algs:
                if signing_key := self._select_key_by_sig_alg(alg):
                    break

            if signing_key:
                return signing_key
            else:
                raise JWSSigningError(
                    f"signing forced by using algs {signing_algs}, but no such key is available"
                )

        # Case 3: only one key
        if signing_key := self._select_signing_key_by_uniqueness():
            return signing_key
        # Case 4: only one *signing* key
        if signing_key := self._select_key_by_use(use="sig"):
            return signing_key
        # Case 5: match key by kid
        if signing_key := self._select_key_by_kid(headers):
            return signing_key
        # Case 6: match key by x5c
        if signing_key := self._select_key_by_x5c(headers):
            return signing_key
        raise JWSSigningError(
            "signing error: not possible to uniquely determine the signing key"
        )

    def _select_signing_key_by_uniqueness(self) -> dict | None:
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()
        return None

    def _select_key_by_use(self, use: str) -> dict | None:
        candidate_signing_keys: list[dict] = []
        for key in self.jwks:
            key_d = key.to_dict()
            if use == key_d.get("use", ""):
                candidate_signing_keys.append(key_d)
        if len(candidate_signing_keys) == 1:
            return candidate_signing_keys[0]
        return None
    
    def _select_key_by_sig_alg(self, alg: str) -> dict | None:
        """
        Select a key based on the signature algorithm.
        This is a helper method to find a key that matches the given signature algorithm.
        """
        for key in self.jwks:
            key_d: dict[str, Any] = key.to_dict()
            if alg == DEFAULT_SIG_KTY_MAP.get(key_d.get("kty", ""), ""):
                return key_d
            
        return None

    def _select_key_by_kid(self, headers: tuple[dict[str, Any], dict[str, Any]]) -> dict | None:
        if not headers:
            return None
        if "kid" in headers[0]:
            kid = headers[0]["kid"]
        elif "kid" in headers[1]:
            kid = headers[1]["kid"]
        else:
            return None
        return find_jwk_by_kid([key.to_dict() for key in self.jwks], kid)

    def _select_key_by_x5c(self, headers: tuple[dict[str, Any], dict[str, Any]]) -> dict | None:
        if not headers:
            return None
        x5c: list[str] | None = headers[0].get("x5c") or headers[1].get("x5c")
        if not x5c:
            return None
        header_jwk = parse_b64der(x5c[0])
        for key in self.jwks:
            key_d = key.to_dict()
            if JWK(key_d).thumbprint == header_jwk.thumbprint:
                return key_d
        return None

    def verify(
        self, jwt: str, tolerance_s: int = DEFAULT_TOKEN_TIME_TOLERANCE
    ) -> str | Any | bytes:
        """Verify a JWS with one of the initialized keys and validate standard
        standard claims if possible, such as 'iat' and 'exp'.
        Verification of tokens in JSON serialization format is not supported.

        :param jwt: The JWS token to be verified.
        :type jws: str
        :param tolerance_s: optional tolerance window, in seconds, which can be \
            used to account for some clock skew between the token issuer and the \
            token verifier when validating lifetime claims.
        :type tolerance_s: int

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
            raise JWSVerificationError(
                f"Verification error: unable to find matching public key for header {header}"
            )

        # sanity check: kid must match if present
        if expected_kid := header.get("kid"):
            obtained_kid = verifying_key.get("kid", None)
            if obtained_kid and (obtained_kid != expected_kid):
                raise JWSVerificationError(
                    KidError(
                        "unexpected verification state: found a valid verifying key,"
                        f"but its kid {obtained_kid} does not match token header kid {expected_kid}"
                    )
                )

        # Verify the JWS compact signature
        verifier = JWS(alg=header["alg"])

        # Validate JWT claims
        try:
            msg: dict = verifier.verify_compact(jwt, [key_from_jwk_dict(verifying_key)])
            validate_jwt_timestamps_claims(msg, tolerance_s)
        except LifetimeException as e:
            raise JWSVerificationError(f"Invalid JWT claims: {e}")
        except Exception as e:
            raise JWSVerificationError(f"Error during signature verification: {e}")

        return msg

    def _select_verifying_key(self, header: dict) -> dict | None:
        available_keys = [key.to_dict() for key in self.jwks]

        # case 1: can be found by header
        if "kid" in header:
            if verifying_key := find_jwk_by_kid(available_keys, header["kid"]):
                return verifying_key

        # case 2: the token is self contained, and the verification key matches one of the key in the whitelist
        if self_contained_claims_key_pair := find_self_contained_key(header):
            # check if the self contained key matches a trusted jwk
            _, candidate_key = self_contained_claims_key_pair
            if hasattr(candidate_key, "thumbprint"):
                if verifying_key := find_jwk_by_thumbprint(
                    available_keys, candidate_key.thumbprint
                ):
                    return verifying_key
                else:
                    logger.error(
                        f"Candidate key {candidate_key} does not have a thumbprint attribute."
                    )
                    raise ValueError("Invalid key: missing thumbprint.")

        # case 3: if only one key and there is no header claim that can identitfy any key, than that MUST
        # be the only valid CANDIDATE key for signature verification
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()
        return None

    def is_sd_jwt(self, token: str) -> bool:
        """
        Determines if the provided JWT is an SD-JWT.

        :param token: The JWT token to inspect.
        :type token: str
        :returns: True if the token is an SD-JWT, False otherwise.
        :rtype: bool
        """
        if not token:
            return False

        try:
            # Decode the JWT header to inspect the 'typ' field
            header = decode_jwt_header(token)

            # Check if 'typ' field exists and is equal to 'sd-jwt'
            return header.get("typ") == "sd-jwt"
        except Exception as e:
            # Log or handle errors (optional)
            logger.warning(f"Unable to determine if token is SD-JWT: {e}")
            return False


def _validate_key_with_header_kid(key: dict, header: dict) -> None:
    """
    :raises Exception: if the key is not compatible with the header content kid (if any)
    """
    if (key_kid := key.get("kid")) and (header_kid := header.get("kid")) and (key_kid != header_kid):
        raise Exception(
            f"token header contains a kid {header_kid} that does not match the signing key kid {key_kid}"
        )
    return


def _validate_key_with_header_x5c(key: dict, header: dict) -> None:
    """
    Validate that a key has a public component that matches what defined in
    the x5c leaf certificate in the header (if any).
    Note that this method DOES NOT validate the chain. Instead, it actually
    checks that the leaf of the chain has the same cryptographic material
    of the argument key.

    :raises Exception: if the key is not compatible with the header content x5c (if any)
    """
    x5c: list[str] | None = header.get("x5c")
    if not x5c:
        return
    leaf_cert: str = x5c[0]

    # if the key has a certificate, check the cert, otherwise check the public material    
    key_x5c: list[str] | None = key.get("x5c")
    if key_x5c:
        if leaf_cert != (leaf_x5c_cert := key_x5c[0]):
            raise Exception(
                f"token header containes a chain whose leaf certificate {leaf_cert} does not match the signing key leaf certificate {leaf_x5c_cert}"\
            )
        return
    header_key = parse_b64der(leaf_cert)
    if header_key.thumbprint != JWK(key).thumbprint:
        raise Exception(
            f"public material of the key does not matches the key in the leaf certificate {leaf_cert}"
        )
    return


def _validate_key_with_jws_header(key: dict, protected_jws_header: dict, unprotected_jws_header: dict) -> None:
    """
    Validate that a key used for some operations (sign, verify) on a token
    is compatible with the token header itself.

    :raises Exception: if the key is not compatible with the token header
    """
    header = deepcopy(protected_jws_header)
    header.update(unprotected_jws_header)
    # NOTE: consistency with usage claims such as 'alg', 'kty' and 'use'
    # are done by the signer library and are not required here
    _validate_key_with_header_kid(key, header)
    _validate_key_with_header_x5c(key, header)
