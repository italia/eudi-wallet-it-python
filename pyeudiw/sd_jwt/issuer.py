import logging
import random
import secrets

from json import dumps
from typing import Dict, List, Union

from pyeudiw.jwt import JWSHelper
from pyeudiw.sd_jwt.common import (
    DEFAULT_SIGNING_ALG,
    DIGEST_ALG_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
    JSON_SER_DISCLOSURE_KEY,
    SDJWTCommon,
    SDObj,
)
from pyeudiw.sd_jwt.disclosure import SDJWTDisclosure

from cryptojwt.jws.jws import JWS
from cryptojwt.jwk.jwk import key_from_jwk_dict

logger = logging.getLogger(__name__)


class SDJWTIssuer(SDJWTCommon):
    DECOY_MIN_ELEMENTS = 2
    DECOY_MAX_ELEMENTS = 5

    sd_jwt_payload: Dict
    sd_jwt: JWS
    serialized_sd_jwt: str

    ii_disclosures: List
    sd_jwt_issuance: str

    decoy_digests: List

    def __init__(
        self,
        user_claims: Dict,
        issuer_keys: Union[Dict, List[Dict]],
        holder_key=None,
        sign_alg=None,
        add_decoy_claims: bool = False,
        extra_header_parameters: dict = {},
    ):
        super().__init__(serialization_format="compact")

        self._user_claims = user_claims
        if not isinstance(issuer_keys, list):
            issuer_keys = [issuer_keys]
        self._issuer_keys = issuer_keys
        self._holder_key = holder_key
        self._sign_alg = sign_alg or DEFAULT_SIGNING_ALG
        self._add_decoy_claims = add_decoy_claims
        self._extra_header_parameters = extra_header_parameters

        self.ii_disclosures = []
        self.decoy_digests = []

        if len(self._issuer_keys) > 1 and self._serialization_format != "json":
            raise ValueError(
                f"Multiple issuer keys (here {len(self._issuer_keys)}) are only supported with JSON serialization."
                f"Keys found: {self._issuer_keys}"
            )

        self._check_for_sd_claim(self._user_claims)
        self._assemble_sd_jwt_payload()
        self._create_signed_jws()
        self._create_combined()

    def _assemble_sd_jwt_payload(self):
        # Create the JWS payload
        self.sd_jwt_payload = self._create_sd_claims(self._user_claims)
        self.sd_jwt_payload.update(
            {
                DIGEST_ALG_KEY: self.HASH_ALG["name"],
            }
        )
        if self._holder_key:
            self.sd_jwt_payload["cnf"] = {
                "jwk": key_from_jwk_dict(self._holder_key).serialize()
            }

    def _create_decoy_claim_entry(self) -> str:
        digest = self._b64hash(self._generate_salt().encode("ascii"))
        self.decoy_digests.append(digest)
        return digest

    def _create_sd_claims(self, user_claims):
        # This function can be called recursively.
        #
        # If the user claims are a list, apply this function
        # to each item in the list.
        if isinstance(user_claims, list):
            return self._create_sd_claims_list(user_claims)

        # If the user claims are a dictionary, apply this function
        # to each key/value pair in the dictionary.
        elif isinstance(user_claims, dict):
            return self._create_sd_claims_object(user_claims)

        # For other types, assume that the value can be disclosed.
        elif isinstance(user_claims, SDObj):
            raise ValueError(
                f"SDObj found in illegal place. The claim value '{user_claims}' should not be wrapped by SDObj."
            )
        return user_claims

    def _create_sd_claims_list(self, user_claims: List):
        # Walk through all elements in the list.
        # If an element is marked as SD, then create a proper disclosure for it.
        # Otherwise, just return the element.

        output_user_claims = []
        for claim in user_claims:
            if isinstance(claim, SDObj):
                subtree_from_here = self._create_sd_claims(claim.value)
                # Create a new disclosure
                disclosure = SDJWTDisclosure(
                    self,
                    key=None,
                    value=subtree_from_here,
                )

                # Add to ii_disclosures
                self.ii_disclosures.append(disclosure)

                # Assemble all hash digests in the disclosures list.
                output_user_claims.append({SD_LIST_PREFIX: disclosure.hash})
            else:
                subtree_from_here = self._create_sd_claims(claim)
                output_user_claims.append(subtree_from_here)

        return output_user_claims

    def _create_sd_claims_object(self, user_claims: Dict):
        sd_claims = {SD_DIGESTS_KEY: []}
        for key, value in user_claims.items():
            subtree_from_here = self._create_sd_claims(value)
            if isinstance(key, SDObj):
                # Create a new disclosure
                disclosure = SDJWTDisclosure(
                    self,
                    key=key.value,
                    value=subtree_from_here,
                )

                # Add to ii_disclosures
                self.ii_disclosures.append(disclosure)

                # Assemble all hash digests in the disclosures list.
                sd_claims[SD_DIGESTS_KEY].append(disclosure.hash)
            else:
                sd_claims[key] = subtree_from_here

        # Add decoy claims if requested
        if self._add_decoy_claims:
            sr = secrets.SystemRandom()
            for _ in range(
                sr.randint(self.DECOY_MIN_ELEMENTS, self.DECOY_MAX_ELEMENTS)
            ):
                sd_claims[SD_DIGESTS_KEY].append(self._create_decoy_claim_entry())

        # Delete the SD_DIGESTS_KEY if it is empty
        if len(sd_claims[SD_DIGESTS_KEY]) == 0:
            del sd_claims[SD_DIGESTS_KEY]
        else:
            # Sort the hash digests otherwise
            sd_claims[SD_DIGESTS_KEY].sort()

        return sd_claims

    def _create_signed_jws(self):
        """
        Create the SD-JWT.

        If serialization_format is "compact", then the SD-JWT is a JWT (JWS in compact serialization).
        If serialization_format is "json", then the SD-JWT is a JWS in JSON serialization. The disclosures in this case
        will be added in a separate "disclosures" property of the JSON.
        """

        # Assemble protected headers starting with default
        _protected_headers = {"alg": self._sign_alg, "typ": self.SD_JWT_HEADER}

        if len(self._issuer_keys) == 1 and "kid" in self._issuer_keys[0]:
            _protected_headers["kid"] = self._issuer_keys[0]["kid"]

        # override if any
        _protected_headers.update(self._extra_header_parameters)

        _unprotected_headers = {}
        for i, key in enumerate(self._issuer_keys):
            _unprotected_headers = {"kid": key["kid"]} if "kid" in key else None
            if self._serialization_format == "json" and i == 0:
                _unprotected_headers = _unprotected_headers or {}
                _unprotected_headers[JSON_SER_DISCLOSURE_KEY] = [d.b64 for d in self.ii_disclosures]

        # self.sd_jwt = JWSHelper(jwks=self._issuer_keys)
        # self.serialized_sd_jwt = self.sd_jwt.sign(
        #     self.sd_jwt_payload,
        #     protected=_protected_headers,
        #     unprotected=_unprotected_headers,
        #     serialization_format=self._serialization_format
        # )
        signer = JWSHelper(jwks=self._issuer_keys)
        self.serialized_sd_jwt = signer.sign(self.sd_jwt_payload, _protected_headers)

    def _create_combined(self):
        if self._serialization_format == "compact":
            self.sd_jwt_issuance = self._combine(
                self.serialized_sd_jwt, *(d.b64 for d in self.ii_disclosures)
            )
            self.sd_jwt_issuance += self.COMBINED_SERIALIZATION_FORMAT_SEPARATOR
        else:
            self.sd_jwt_issuance = self.serialized_sd_jwt
