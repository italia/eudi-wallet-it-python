import logging
from typing import Callable, Dict, List, Union

from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.helper import validate_jwt_timestamps_claims
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.sd_jwt.common import SDJWTCommon

from . import (DEFAULT_SIGNING_ALG, DIGEST_ALG_KEY, KB_DIGEST_KEY,
               SD_DIGESTS_KEY, SD_LIST_PREFIX)

logger = logging.getLogger(__name__)


class SDJWTVerifier(SDJWTCommon):
    _input_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(
        self,
        sd_jwt_presentation: str,
        cb_get_issuer_key: Callable[[str, Dict], str],
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        serialization_format: str = "compact",
    ):
        super().__init__(serialization_format=serialization_format)

        self._parse_sd_jwt(sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        self._verify_sd_jwt(cb_get_issuer_key)

        # expected aud and nonce either need to be both set or both None
        if expected_aud or expected_nonce:
            if not (expected_aud and expected_nonce):
                raise ValueError(
                    "Either both expected_aud and expected_nonce must be provided or both must be None"
                )

            # Verify the SD-JWT-Release
            self._verify_key_binding_jwt(
                expected_aud,
                expected_nonce,
            )

    def get_verified_payload(self):
        return self._extract_sd_claims()

    def _verify_sd_jwt(
        self,
        cb_get_issuer_key,
        sign_alg: str = None,
    ):
        parsed_input_sd_jwt = JWS(alg=sign_alg)

        if self._serialization_format == "json":
            _deserialize_sd_jwt_payload: dict = decode_jwt_header(
                self._unverified_input_sd_jwt_parsed["payload"]
            )
            unverified_issuer = _deserialize_sd_jwt_payload.get("iss", None)
            unverified_header_parameters = self._unverified_input_sd_jwt_parsed['header']
            issuer_public_key_input = cb_get_issuer_key(
                unverified_issuer, unverified_header_parameters)

            issuer_public_key = []
            for key in issuer_public_key_input:
                if not isinstance(key, dict):
                    raise ValueError(
                        "The issuer_public_key must be a list of JWKs. "
                        f"Found: {type(key)} in {issuer_public_key}"
                    )
                key = key_from_jwk_dict(key)
                issuer_public_key.append(key)

            self._sd_jwt_payload = parsed_input_sd_jwt.verify_json(
                jws=self._unverified_input_sd_jwt,
                keys=issuer_public_key
            )

        elif self._serialization_format == "compact":
            unverified_header_parameters = decode_jwt_header(
                self._unverified_input_sd_jwt)
            sign_alg = sign_alg or unverified_header_parameters.get(
                "alg", DEFAULT_SIGNING_ALG)

            parsed_input_sd_jwt = JWS(alg=sign_alg)
            parsed_payload = decode_jwt_payload(self._unverified_input_sd_jwt)
            unverified_issuer = parsed_payload.get("iss", None)
            header_params = unverified_header_parameters.copy()

            issuer_public_key_input = cb_get_issuer_key(
                unverified_issuer, header_params
            )

            issuer_public_key = []
            for key in issuer_public_key_input:
                if not isinstance(key, dict):
                    raise ValueError(
                        "The issuer_public_key must be a list of JWKs. "
                        f"Found: {type(key)} in {issuer_public_key}"
                    )
                key = key_from_jwk_dict(key)
                issuer_public_key.append(key)

            self._sd_jwt_payload = parsed_input_sd_jwt.verify_compact(
                jws=self._unverified_input_sd_jwt,
                keys=issuer_public_key,
                sigalg=sign_alg
            )

            try:
                validate_jwt_timestamps_claims(self._sd_jwt_payload)
            except ValueError as e:
                raise JWSVerificationError(f"Invalid JWT claims: {e}")

        else:
            raise ValueError(
                f"Unsupported serialization format: {self._serialization_format}"
            )

        self._holder_public_key_payload = self._sd_jwt_payload.get("cnf", None)

    def _verify_key_binding_jwt(
        self,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        sign_alg: Union[str, None] = None,
    ):

        # Deserialized the key binding JWT
        sign_alg or DEFAULT_SIGNING_ALG

        # Verify the key binding JWT using the holder public key
        if self._serialization_format == "json":
            decode_jwt_header(
                self._unverified_input_sd_jwt_parsed["payload"]
            )

        holder_public_key_payload_jwk = self._holder_public_key_payload.get(
            "jwk", None)

        if not holder_public_key_payload_jwk:
            raise ValueError(
                "The holder_public_key_payload is malformed. "
                "It doesn't contain the claim jwk: "
                f"{self._holder_public_key_payload}"
            )

        pubkey = key_from_jwk_dict(holder_public_key_payload_jwk)

        parsed_input_key_binding_jwt = JWSHelper(jwks=pubkey)
        verified_payload = parsed_input_key_binding_jwt.verify(
            self._unverified_input_key_binding_jwt)

        key_binding_jwt_header = decode_jwt_header(
            self._unverified_input_key_binding_jwt)

        if key_binding_jwt_header["typ"] != self.KB_JWT_TYP_HEADER:
            raise ValueError("Invalid header typ")

        # Check payload
        key_binding_jwt_payload = verified_payload

        if key_binding_jwt_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience in KB-JWT")
        if key_binding_jwt_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce in KB-JWT")

        # Reassemble the SD-JWT in compact format and check digest
        if self._serialization_format == "compact":
            expected_sd_jwt_presentation_hash = self._calculate_kb_hash(
                self._input_disclosures
            )

            if (
                key_binding_jwt_payload[KB_DIGEST_KEY]
                != expected_sd_jwt_presentation_hash
            ):
                raise ValueError("Invalid digest in KB-JWT")

    def _extract_sd_claims(self):
        if DIGEST_ALG_KEY in self._sd_jwt_payload:
            if self._sd_jwt_payload[DIGEST_ALG_KEY] != self.HASH_ALG["name"]:
                # TODO: Support other hash algorithms
                raise ValueError("Invalid hash algorithm")

        self._duplicate_hash_check = []
        return self._unpack_disclosed_claims(self._sd_jwt_payload)

    def _unpack_disclosed_claims(self, sd_jwt_claims):
        # In a list, unpack each element individually
        if type(sd_jwt_claims) is list:
            output = []
            for element in sd_jwt_claims:
                if (
                    type(element) is dict
                    and len(element) == 1
                    and SD_LIST_PREFIX in element
                    and type(element[SD_LIST_PREFIX]) is str
                ):
                    digest_to_check = element[SD_LIST_PREFIX]
                    if digest_to_check in self._hash_to_decoded_disclosure:
                        _, value = self._hash_to_decoded_disclosure[digest_to_check]
                        output.append(self._unpack_disclosed_claims(value))
                else:
                    output.append(self._unpack_disclosed_claims(element))
            return output

        elif type(sd_jwt_claims) is dict:
            # First, try to figure out if there are any claims to be
            # disclosed in this dict. If so, replace them by their
            # disclosed values.

            pre_output = {
                k: self._unpack_disclosed_claims(v)
                for k, v in sd_jwt_claims.items()
                if k != SD_DIGESTS_KEY and k != DIGEST_ALG_KEY
            }

            for digest in sd_jwt_claims.get(SD_DIGESTS_KEY, []):
                if digest in self._duplicate_hash_check:
                    raise ValueError(
                        f"Duplicate hash found in SD-JWT: {digest}")
                self._duplicate_hash_check.append(digest)

                if digest in self._hash_to_decoded_disclosure:
                    _, key, value = self._hash_to_decoded_disclosure[digest]
                    if key in pre_output:
                        raise ValueError(
                            "Duplicate key found when unpacking disclosed claim: "
                            f"'{key}' in {pre_output}. This is not allowed."
                        )
                    unpacked_value = self._unpack_disclosed_claims(value)
                    pre_output[key] = unpacked_value

            # Now, go through the dict and unpack any nested dicts.

            return pre_output

        else:
            return sd_jwt_claims
