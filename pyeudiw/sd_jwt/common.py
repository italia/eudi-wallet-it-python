import logging
import os
import random
import secrets

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
from json import loads
from typing import List

DEFAULT_SIGNING_ALG = "ES256"
SD_DIGESTS_KEY = "_sd"
DIGEST_ALG_KEY = "_sd_alg"
KB_DIGEST_KEY = "sd_hash"
SD_LIST_PREFIX = "..."
JSON_SER_DISCLOSURE_KEY = "disclosures"
JSON_SER_KB_JWT_KEY = "kb_jwt"

logger = logging.getLogger("sd_jwt")


@dataclass
class SDObj:
    """This class can be used to make this part of the object selective disclosable."""

    value: any

    # Make hashable
    def __hash__(self):
        return hash(self.value)


class SDJWTHasSDClaimException(Exception):
    """Exception raised when input data contains the special _sd claim reserved for SD-JWT internal data."""

    def __init__(self, error_location: any):
        super().__init__(
            f"Input data contains the special claim '{SD_DIGESTS_KEY}' reserved for SD-JWT internal data. Location: {error_location!r}"
        )


class SDJWTCommon:
    SD_JWT_HEADER = os.getenv(
        "SD_JWT_HEADER", "example+sd-jwt"
    )  # overwriteable with extra_header_parameters = {"typ": "other-example+sd-jwt"}
    KB_JWT_TYP_HEADER = "kb+jwt"
    HASH_ALG = {"name": "sha-256", "fn": sha256}

    COMBINED_SERIALIZATION_FORMAT_SEPARATOR = "~"

    unsafe_randomness = False

    def __init__(self, serialization_format):
        if serialization_format not in ("compact", "json"):
            raise ValueError(f"Unknown serialization format: {serialization_format}")
        self._serialization_format = serialization_format

    def _b64hash(self, raw):
        # Calculate the SHA 256 hash and output it base64 encoded
        return self._base64url_encode(self.HASH_ALG["fn"](raw).digest())

    def _combine(self, *parts):
        return self.COMBINED_SERIALIZATION_FORMAT_SEPARATOR.join(parts)

    def _split(self, combined):
        return combined.split(self.COMBINED_SERIALIZATION_FORMAT_SEPARATOR)

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        return urlsafe_b64encode(data).decode("ascii").strip("=")

    @staticmethod
    def _base64url_decode(b64data: str) -> bytes:
        padded = f"{b64data}{'=' * divmod(len(b64data),4)[1]}"
        return urlsafe_b64decode(padded)

    def _generate_salt(self):
        if self.unsafe_randomness:
            # This is not cryptographically secure, but it is deterministic
            # and allows for repeatable output for the generation of the examples.
            logger.warning(
                "Using unsafe randomness is not suitable for production use."
            )
            return self._base64url_encode(
                bytes(random.getrandbits(8) for _ in range(16))
            )
        else:
            return self._base64url_encode(secrets.token_bytes(16))

    def _create_hash_mappings(self, disclosurses_list: List):
        # Mapping from hash of disclosure to the decoded disclosure
        self._hash_to_decoded_disclosure = {}

        # Mapping from hash of disclosure to the raw disclosure
        self._hash_to_disclosure = {}

        for disclosure in disclosurses_list:
            decoded_disclosure = loads(
                self._base64url_decode(disclosure).decode("utf-8")
            )
            _hash = self._b64hash(disclosure.encode("ascii"))
            if _hash in self._hash_to_decoded_disclosure:
                raise ValueError(
                    f"Duplicate disclosure hash {_hash} for disclosure {decoded_disclosure}"
                )

            self._hash_to_decoded_disclosure[_hash] = decoded_disclosure
            self._hash_to_disclosure[_hash] = disclosure

    def _check_for_sd_claim(self, the_object):
        # Recursively check for the presence of the _sd claim, also
        # works for arrays and nested objects.
        if isinstance(the_object, dict):
            for key, value in the_object.items():
                if key == SD_DIGESTS_KEY:
                    raise SDJWTHasSDClaimException(the_object)
                else:
                    self._check_for_sd_claim(value)
        elif isinstance(the_object, list):
            for item in the_object:
                self._check_for_sd_claim(item)
        else:
            return

    def _parse_sd_jwt(self, sd_jwt):
        if self._serialization_format == "compact":
            (
                self._unverified_input_sd_jwt,
                *self._input_disclosures,
                self._unverified_input_key_binding_jwt
            ) = self._split(sd_jwt)

            # Extract only the body from SD-JWT without verifying the signature
            _, jwt_body, _ = self._unverified_input_sd_jwt.split(".")
            self._unverified_input_sd_jwt_payload = loads(
                self._base64url_decode(jwt_body)
            )
            self._unverified_compact_serialized_input_sd_jwt = (
                self._unverified_input_sd_jwt
            )

        else:
            # if the SD-JWT is in JSON format, parse the json and extract the disclosures.
            self._unverified_input_sd_jwt = sd_jwt
            self._unverified_input_sd_jwt_parsed = loads(sd_jwt)

            self._unverified_input_sd_jwt_payload = loads(
                self._base64url_decode(self._unverified_input_sd_jwt_parsed["payload"])
            )

            # distinguish between flattened and general JSON serialization (RFC7515)
            if "signature" in self._unverified_input_sd_jwt_parsed:
                # flattened
                self._input_disclosures = self._unverified_input_sd_jwt_parsed[
                    "header"
                ][JSON_SER_DISCLOSURE_KEY]
                self._unverified_input_key_binding_jwt = (
                    self._unverified_input_sd_jwt_parsed["header"].get(
                        JSON_SER_KB_JWT_KEY, ""
                    )
                )
                self._unverified_compact_serialized_input_sd_jwt = ".".join(
                    [
                        self._unverified_input_sd_jwt_parsed["protected"],
                        self._unverified_input_sd_jwt_parsed["payload"],
                        self._unverified_input_sd_jwt_parsed["signature"]
                    ]
                )

            elif "signatures" in self._unverified_input_sd_jwt_parsed:
                # general, look at the header in the first signature
                self._input_disclosures = self._unverified_input_sd_jwt_parsed[
                    "signatures"
                ][0]["header"][JSON_SER_DISCLOSURE_KEY]
                self._unverified_input_key_binding_jwt = (
                    self._unverified_input_sd_jwt_parsed["signatures"][0]["header"].get(
                        JSON_SER_KB_JWT_KEY, ""
                    )
                )
                self._unverified_compact_serialized_input_sd_jwt = ".".join(
                    [
                        self._unverified_input_sd_jwt_parsed["signatures"][0][
                            "protected"
                        ],
                        self._unverified_input_sd_jwt_parsed["payload"],
                        self._unverified_input_sd_jwt_parsed["signatures"][0][
                            "signature"
                        ],
                    ]
                )

            else:
                raise ValueError("Invalid JSON serialization of SD-JWT")

    def _calculate_kb_hash(self, disclosures):
        # Temporarily create the combined presentation in order to create the hash over it
        # Note: For JSON Serialization, the compact representation of the SD-JWT is restored from the parsed JSON (see common.py)
        string_to_hash = self._combine(
            self._unverified_compact_serialized_input_sd_jwt,
            *disclosures,
            ""
        )
        return self._b64hash(string_to_hash.encode("ascii"))