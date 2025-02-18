import logging
from itertools import zip_longest
from json import dumps, loads
from time import time
from typing import Dict, List, Optional, Union
from pyeudiw.jwt.helper import KeyLike

from cryptojwt.jws.jws import JWS

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.sd_jwt import (
    DEFAULT_SIGNING_ALG,
    JSON_SER_DISCLOSURE_KEY,
    JSON_SER_KB_JWT_KEY,
    KB_DIGEST_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
)
from pyeudiw.sd_jwt.common import SDJWTCommon

logger = logging.getLogger(__name__)

class SDJWTHolder(SDJWTCommon):
    """
    SDJWTHolder is a class to create a holder presentation from a SD-JWT.
    """

    hs_disclosures: List
    key_binding_jwt_header: Dict
    key_binding_jwt_payload: Dict
    serialized_key_binding_jwt: str = ""
    sd_jwt_presentation: str

    _input_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    def __init__(
            self, 
            sd_jwt_issuance: str, 
            serialization_format: str = "compact") -> None:
        """
        Creates an instance of SDJWTHolder.

        :param sd_jwt_issuance: The SD-JWT to create a presentation from.
        :param serialization_format: The serialization format of the SD-JWT.

        :param serialization_format: The serialization format of the SD-JWT.
        :type serialization_format: str
        """
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
        self, 
        claims_to_disclose: Union[dict, True, None],
        nonce: Union[str, None] = None, 
        aud: Union[str, None] = None, 
        holder_key: Union[KeyLike, None] = None, 
        sign_alg: Union[str, None] = None
    ) -> None:
        """
        Create a holder presentation from the SD-JWT.

        :param claims_to_disclose: The claims to disclose. If True, all claims are disclosed.
        :param nonce: The nonce to include in the key binding JWT.
        :param aud: The audience to include in the key binding JWT.
        :param holder_key: The key to sign the key binding JWT with.
        :param sign_alg: The signing algorithm to use for the key binding JWT.
        """

        # Select the disclosures
        self.hs_disclosures = []

        self._select_disclosures(self.sd_jwt_payload, claims_to_disclose)

        # Optional: Create a key binding JWT
        if nonce and aud and holder_key:
            sd_jwt_presentation_hash = self._calculate_kb_hash(self.hs_disclosures)
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

    def _select_disclosures(
            self, 
            sd_jwt_claims: Union[bytes, list, dict], 
            claims_to_disclose: Union[dict, True, None]) -> Union[dict, list, None]:
        """
        Recursively process the claims in sd_jwt_claims. In each
        object found therein, look at the SD_DIGESTS_KEY. If it
        contains hash digests for claims that should be disclosed,
        then add the corresponding disclosures to the claims_to_disclose.

        :param sd_jwt_claims: The claims to process.
        :param claims_to_disclose: The claims to disclose.

        :type sd_jwt_claims: bytes | list | dict
        :type claims_to_disclose: dict | True | None


        :returns: The claims to disclose.
        :rtype: dict | list | None
        """

        if type(sd_jwt_claims) is bytes:
            return self._select_disclosures_dict(
                loads(self.sd_jwt_payload.decode("utf-8")), claims_to_disclose
            )
        if type(sd_jwt_claims) is list:
            return self._select_disclosures_list(sd_jwt_claims, claims_to_disclose)
        elif type(sd_jwt_claims) is dict:
            return self._select_disclosures_dict(sd_jwt_claims, claims_to_disclose)
        else:
            pass

    def _select_disclosures_list(
            self, 
            sd_jwt_claims: list, 
            claims_to_disclose: Union[list, True, None]) -> list:
        
        """
        Process the claims in a list.

        :param sd_jwt_claims: The claims to process.
        :param claims_to_disclose: The claims to disclose.

        :type sd_jwt_claims: list
        :type claims_to_disclose: list | True | None

        :raises ValueError: If the disclosure information is not an array.

        :returns: The claims to disclose.
        :rtype: list
        """

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

                self.hs_disclosures.append(self._hash_to_disclosure[digest_to_check])
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

    def _select_disclosures_dict(
            self, 
            sd_jwt_claims: dict, 
            claims_to_disclose: Union[dict, True, None]):
        """
        Process the claims in a dictionary.

        :param sd_jwt_claims: The claims to process.
        :param claims_to_disclose: The claims to disclose.

        :type sd_jwt_claims: dict
        :type claims_to_disclose: dict | True | None

        :raises ValueError: If the disclosure information is not a dictionary.

        :returns: The claims to disclose.
        :rtype: dict
        """

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
                            logger.debug(f"Adding disclosure for {digest_to_check}")
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

                    self._select_disclosures(value, claims_to_disclose.get(key, None))
            else:
                self._select_disclosures(value, claims_to_disclose.get(key, None))

    def _create_key_binding_jwt(
        self, 
        nonce: Union[str, None], 
        aud: Union[str, None], 
        presentation_hash, 
        holder_key: Union[KeyLike | list[KeyLike | dict] | dict], 
        sign_alg: Optional[str] = None
    ) -> None:
        """
        Create a key binding JWT.

        :param nonce: The nonce to include in the key binding JWT.
        :param aud: The audience to include in the key binding JWT.
        :param presentation_hash: The hash of the presentation.
        :param holder_key: The key to sign the key binding JWT with.
        :param sign_alg: The signing algorithm to use for the key binding JWT.
        """

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
            kid_in_header=False,
        )
