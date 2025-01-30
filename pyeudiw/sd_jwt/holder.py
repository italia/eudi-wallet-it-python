import logging

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.sd_jwt.common import SDJWTCommon

from pyeudiw.sd_jwt import (
    DEFAULT_SIGNING_ALG,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
    KB_DIGEST_KEY,
    JSON_SER_DISCLOSURE_KEY,
    JSON_SER_KB_JWT_KEY,
)
from json import dumps
from time import time
from typing import Dict, List, Optional
from itertools import zip_longest

from cryptojwt.jws.jws import JWS
from json import dumps, loads

logger = logging.getLogger(__name__)


class SDJWTHolder(SDJWTCommon):
    hs_disclosures: List
    key_binding_jwt_header: Dict
    key_binding_jwt_payload: Dict
    key_binding_jwt: JWS
    serialized_key_binding_jwt: str = ""
    sd_jwt_presentation: str

    _input_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(self, sd_jwt_issuance: str, serialization_format: str = "compact"):
        super().__init__(serialization_format=serialization_format)

        self._parse_sd_jwt(sd_jwt_issuance)

        # TODO: This holder does not verify the SD-JWT yet - this
        # is not strictly needed, but it would be nice to have.
        self.serialized_sd_jwt = self._unverified_input_sd_jwt
        self.sd_jwt_payload = self._unverified_input_sd_jwt_payload
        if self._serialization_format == "json":
            self.sd_jwt_parsed = self._unverified_input_sd_jwt_parsed

        self._create_hash_mappings(self._input_disclosures)

    def create_presentation(
        self, claims_to_disclose, nonce=None, aud=None, holder_key=None, sign_alg=None
    ):
        # Select the disclosures
        self.hs_disclosures = []

        self._select_disclosures(self.sd_jwt_payload, claims_to_disclose)

        # Optional: Create a key binding JWT
        if nonce and aud and holder_key:
            sd_jwt_presentation_hash = self._calculate_kb_hash(
                self.hs_disclosures)
            self._create_key_binding_jwt(
                nonce, aud, sd_jwt_presentation_hash, holder_key, sign_alg
            )

        # Create the combined presentation
        if self._serialization_format == "compact":
            # Note: If the key binding JWT is not created, then the
            # last element is empty, matching the spec.
            self.sd_jwt_presentation = self._combine(
                self.serialized_sd_jwt,
                *self.hs_disclosures,
                self.serialized_key_binding_jwt,
            )
        else:
            # In this case, take the parsed JSON serialized SD-JWT and
            # only filter the disclosures in the header. Add the key
            # binding JWT to the header if it was created.
            presentation = self._unverified_input_sd_jwt_parsed
            if "signature" in presentation:
                # flattened JSON serialization
                presentation["header"][JSON_SER_DISCLOSURE_KEY] = self.hs_disclosures

                if self.serialized_key_binding_jwt:
                    presentation["header"][
                        JSON_SER_KB_JWT_KEY
                    ] = self.serialized_key_binding_jwt
            else:
                # general, add everything to first signature's header
                presentation["signatures"][0]["header"][
                    JSON_SER_DISCLOSURE_KEY
                ] = self.hs_disclosures

                if self.serialized_key_binding_jwt:
                    presentation["signatures"][0]["header"][
                        JSON_SER_KB_JWT_KEY
                    ] = self.serialized_key_binding_jwt

            self.sd_jwt_presentation = dumps(presentation)

    def _select_disclosures(self, sd_jwt_claims, claims_to_disclose):
        # Recursively process the claims in sd_jwt_claims. In each
        # object found therein, look at the SD_DIGESTS_KEY. If it
        # contains hash digests for claims that should be disclosed,
        # then add the corresponding disclosures to the claims_to_disclose.

        if (type(sd_jwt_claims) is bytes):
            return self._select_disclosures_dict(loads(self.sd_jwt_payload.decode('utf-8')), claims_to_disclose)
        if type(sd_jwt_claims) is list:
            return self._select_disclosures_list(sd_jwt_claims, claims_to_disclose)
        elif type(sd_jwt_claims) is dict:
            return self._select_disclosures_dict(sd_jwt_claims, claims_to_disclose)
        else:
            pass

    def _select_disclosures_list(self, sd_jwt_claims, claims_to_disclose):
        if claims_to_disclose is None:
            return []
        if claims_to_disclose is True:
            claims_to_disclose = []
        if not type(claims_to_disclose) is list:
            raise ValueError(
                f"To disclose array elements, an array must be provided as disclosure information.\n"
                f"Found {claims_to_disclose} instead.\n"
                f"Check disclosure information for array: {sd_jwt_claims}"
            )

        for pos, (claims_to_disclose_element, element) in enumerate(
            zip_longest(claims_to_disclose, sd_jwt_claims, fillvalue=None)
        ):
            if (
                isinstance(element, dict)
                and len(element) == 1
                and SD_LIST_PREFIX in element
                and type(element[SD_LIST_PREFIX]) is str
            ):
                digest_to_check = element[SD_LIST_PREFIX]
                if digest_to_check not in self._hash_to_decoded_disclosure:
                    # fake digest
                    continue

                # Determine type of disclosure
                _, disclosure_value = self._hash_to_decoded_disclosure[digest_to_check]

                # Disclose the claim only if in claims_to_disclose (assumed to be an array)
                # there is an element with the current index and it is not None or False
                if claims_to_disclose_element in (
                    False,
                    None,
                ):
                    continue

                self.hs_disclosures.append(
                    self._hash_to_disclosure[digest_to_check])
                if isinstance(disclosure_value, dict):
                    if claims_to_disclose_element is True:
                        # Tolerate a "True" for a disclosure of an object
                        claims_to_disclose_element = {}
                    if not isinstance(claims_to_disclose_element, dict):
                        raise ValueError(
                            f"To disclose object elements in arrays, provide an object (can be empty).\n"
                            f"Found {claims_to_disclose_element} instead.\n"
                            f"Problem at position {pos} of {claims_to_disclose}.\n"
                            f"Check disclosure information for object: {sd_jwt_claims}"
                        )
                    self._select_disclosures(
                        disclosure_value, claims_to_disclose_element
                    )
                elif isinstance(disclosure_value, list):
                    if claims_to_disclose_element is True:
                        # Tolerate a "True" for a disclosure of an array
                        claims_to_disclose_element = []
                    if not isinstance(claims_to_disclose_element, list):
                        raise ValueError(
                            f"To disclose array elements nested in arrays, provide an array (can be empty).\n"
                            f"Found {claims_to_disclose_element} instead.\n"
                            f"Problem at position {pos} of {claims_to_disclose}.\n"
                            f"Check disclosure information for array: {sd_jwt_claims}"
                        )

                    self._select_disclosures(
                        disclosure_value, claims_to_disclose_element
                    )

            else:
                self._select_disclosures(element, claims_to_disclose_element)

    def _select_disclosures_dict(self, sd_jwt_claims, claims_to_disclose):
        if claims_to_disclose is None:
            return {}
        if claims_to_disclose is True:
            # Tolerate a "True" for a disclosure of an object
            claims_to_disclose = {}
        if not isinstance(claims_to_disclose, dict):
            raise ValueError(
                f"To disclose object elements, an object must be provided as disclosure information.\n"
                f"Found {claims_to_disclose} (type {type(claims_to_disclose)}) instead.\n"
                f"Check disclosure information for object: {sd_jwt_claims}"
            )
        for key, value in sd_jwt_claims.items():
            if key == SD_DIGESTS_KEY:
                for digest_to_check in value:
                    if digest_to_check not in self._hash_to_decoded_disclosure:
                        # fake digest
                        continue
                    _, key, value = self._hash_to_decoded_disclosure[digest_to_check]

                    try:
                        logger.debug(
                            f"In _select_disclosures_dict: {key}, {value}, {claims_to_disclose}"
                        )
                        if key in claims_to_disclose and claims_to_disclose[key]:
                            logger.debug(
                                f"Adding disclosure for {digest_to_check}")
                            self.hs_disclosures.append(
                                self._hash_to_disclosure[digest_to_check]
                            )
                        else:
                            logger.debug(
                                f"Not adding disclosure for {digest_to_check}, {key} (type {type(key)}) not in {claims_to_disclose}"
                            )
                    except TypeError:
                        # claims_to_disclose is not a dict
                        raise TypeError(
                            f"claims_to_disclose does not contain a dict where a dict was expected (found {claims_to_disclose} instead)\n"
                            f"Check claims_to_disclose for key: {key}, value: {value}"
                        ) from None

                    self._select_disclosures(
                        value, claims_to_disclose.get(key, None))
            else:
                self._select_disclosures(
                    value, claims_to_disclose.get(key, None))

    def _create_key_binding_jwt(
        self, nonce, aud, presentation_hash, holder_key, sign_alg: Optional[str] = None
    ):
        _alg = sign_alg or DEFAULT_SIGNING_ALG

        self.key_binding_jwt_header = {
            "alg": _alg,
            "typ": self.KB_JWT_TYP_HEADER,
        }

        self.key_binding_jwt_payload = {
            "nonce": nonce,
            "aud": aud,
            "iat": int(time()),
            KB_DIGEST_KEY: presentation_hash,
        }

        signer = JWSHelper(holder_key)
        self.serialized_key_binding_jwt = signer.sign(
            self.key_binding_jwt_payload,
            protected=self.key_binding_jwt_header,
            kid_in_header=False
        )
