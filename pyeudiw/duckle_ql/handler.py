import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

import jwt
from jwt.algorithms import RSAAlgorithm, ECAlgorithm, RSAPSSAlgorithm, OKPAlgorithm

from pyeudiw.duckle_ql.attribute_mapper import AttributeMapper
from pyeudiw.duckle_ql.credential import DcqlQuery, DcqlMdocCredential, MSO_MDOC_FORMAT, TOKEN_FORMAT_FIELD, \
    DcqlCredential
from pyeudiw.duckle_ql.criteria import match_credential
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

EXP_CLAIM = "exp"
SUB_CLAIM = "sub"
DECODE_OPT = {"verify_signature": False}
QUERY_CONFIG = "query"
DCQL_QUERY_TOKEN = "dcql_query"
CREDENTIALS = "credentials"
METADATA_JWKS_CONFIG_KEY = "metadata_jwks"
DUCKLE_PRESENTATION = "presentation"

class DuckleHandler(BaseVPParser):
    """Handler for processing Verifiable Presentations using DCQL."""

    def __init__(self, trust_evaluator: CombinedTrustEvaluator, sig_alg_supported: list[str] = None, **kwargs) -> None:
        """
        Initialize the DuckleHandler with the trust evaluator.

        :param trust_evaluator: The trust evaluator instance.
        :type trust_evaluator: CombinedTrustEvaluator
        :param sig_alg_supported: List of supported signature algorithms.
        :type sig_alg_supported: list[str]
        """
        super().__init__(trust_evaluator, **kwargs)
        if sig_alg_supported is None:
            sig_alg_supported = []
        self.sig_alg_supported = sig_alg_supported
        self.public_keys = kwargs.get(METADATA_JWKS_CONFIG_KEY, [])
        self.queries = _to_dcql_query(kwargs.get(QUERY_CONFIG, []))
        self.parser_presentation = kwargs.get(DUCKLE_PRESENTATION, [])


    def parse(self,  token: str) -> Dict[str, Any]:
        """
        Parse the Duckle Verifiable Presentation.

        :return: A dictionary representing the parsed presentation.
        :rtype: dict
        """
        try:
            decoded_token = jwt.decode(token,
                              options=DECODE_OPT)
            if DCQL_QUERY_TOKEN not in decoded_token:
                raise ValueError('Invalid token payload: Missing DCQL query')

            credentials = decoded_token[DCQL_QUERY_TOKEN][CREDENTIALS]
            if not credentials:
                raise ValueError('Invalid token payload: Missing credentials in DCQL token')
            dcql_cred = _to_credentials(credentials)
            match_credential(self.queries, dcql_cred)
            attribute_mapper = AttributeMapper(self.parser_presentation)
            return attribute_mapper.apply_mappings(credentials)
        except Exception as e:
                logging.error(f"Unexpected error during unverified parsing: {e}")
                return None

    def validate(
        self,
        token: str,
        verifier_id: str,
        verifier_nonce: str,
    ) -> None:
        """
        Parse the Duckle token, validating the signature and claims.

        :param token: The Duckle token string.
        :type token: str
        :param verifier_id: The verifier's ID (used for the audience claim).
        :type verifier_id: str
        :param verifier_nonce: The verifier's nonce.
        :type verifier_nonce: str
        :raises ValueError: If the signature or claims are invalid.
        """
        if not self.validate_signature(token, verifier_id):
            raise ValueError("Invalid signature for DCQL token")
        try:
            # Decode the token without verifying the signature (already done) to get the claims
            header = jwt.get_unverified_header(token)
            claims = jwt.decode(token,
                                self.sig_alg_supported,
                                algorithms=[_get_header_alg(header)],
                                options=DECODE_OPT)
            if not self.validate_claims(claims):
                raise ValueError("Invalid claims")
        except Exception as e:
            raise ValueError(f"Error during validating DCQL token: {e}")


    def validate_signature(self, token: str, verifier_id: str) -> bool:
        """
        Validate the signature of the Duckle token using the public key.

        :param token: The Duckle token string.
        :type token: str
        :param verifier_id: The verifier's ID (used for the audience claim).
        :type verifier_id: str
        :return: True if the signature is valid, False otherwise.
        :rtype: bool
        """
        if not self.public_keys:
            logging.warning("Missing public keys, unable to check signature for DCQL token.")
            return True
        try:
            header = jwt.get_unverified_header(token)
            algorithm = _get_header_alg(header)
            public_key = self._get_public_key_from_jwk(algorithm)
            jwt.decode(token,
                       public_key,
                       algorithms=[algorithm],
                       audience=verifier_id)
            return True
        except Exception as e:
            logging.error(f"Error during check signature for DCQL token: {e}")
            return False

    def validate_claims(self, claims: Dict[str, Any]) -> bool:
        """
        Perform additional validation on the claims of the token.

        This is where you can add logic specific to Duckle tokens.

        :param claims: A dictionary containing the claims of the token.
        :type claims: dict
        :return: True if all validations pass, False otherwise.
        :rtype: bool
        """
        if SUB_CLAIM not in claims:
            logging.error("Missing mandatory 'sub' claim!")
            return False
        if EXP_CLAIM not in claims:
            logging.error("Missing mandatory 'exp' claim!")
            return False
        if EXP_CLAIM in claims:
            expiry_timestamp = claims[EXP_CLAIM]
            if datetime.fromtimestamp(expiry_timestamp, tz=timezone.utc) < datetime.now(timezone.utc):
                logging.error("DCQL token expired!")
                return False
        return True

    def _get_public_key_from_jwk(self, algorithm: str) -> Any:
        """
        Retrieve the appropriate public key object based on the provided algorithm.

        :param algorithm: The algorithm to use (e.g., 'RS256', 'ES256', 'EdDSA').
        :type algorithm: str
        :return: The public key object corresponding to the selected algorithm.
        :rtype: Any
        :raises ValueError: If no matching key is found for the algorithm.
        """
        # Find the key in JWKS that matches the provided algorithm
        key = next((key for key in self.public_keys if key['alg'] == algorithm), None)

        if key is None:
            raise ValueError(f"No key found for the algorithm: {algorithm}")

        switch = {
            "RS256": lambda: RSAAlgorithm.from_jwk(key),
            "RS384": lambda: RSAAlgorithm.from_jwk(key),
            "RS512": lambda: RSAAlgorithm.from_jwk(key),
            "ES256": lambda: ECAlgorithm.from_jwk(key),
            "ES256K": lambda: ECAlgorithm.from_jwk(key),
            "ES384": lambda: ECAlgorithm.from_jwk(key),
            "ES521": lambda: ECAlgorithm.from_jwk(key),
            "ES512": lambda: ECAlgorithm.from_jwk(key),
            "PS256": lambda: RSAPSSAlgorithm.from_jwk(key),
            "PS384": lambda: RSAPSSAlgorithm.from_jwk(key),
            "PS512": lambda: RSAPSSAlgorithm.from_jwk(key),
            "EdDSA": lambda: OKPAlgorithm.from_jwk(key),
        }
        decode_func = switch.get(algorithm)
        if decode_func is None:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return decode_func()

def _get_header_alg(header: dict[str, Any] ) -> str:
    """
    Extract the algorithm from the JWT header.

    :param header: The JWT header as a dictionary.
    :type header: dict
    :return: The algorithm used in the JWT (e.g., 'RS256', 'ES256').
    :rtype: str
    """
    return header.get('alg')

def _to_dcql_query(config_queries: list) -> list[DcqlQuery]:
    dcql_queries = []
    query_set = set()
    for q in config_queries:
        query_dict = DcqlQuery.parse(json.loads(q))
        query_key = (query_dict.id, query_dict.format)
        if query_key in query_set:
            raise ValueError(f"Duplicate query found with id: {query_dict.id} and format: {query_dict.format}")
        query_set.add(query_key)
        dcql_queries.append(query_dict)
    return dcql_queries

def _to_credentials(token_credentials: list[dict]) -> list[DcqlCredential]:
    credentials = []
    for c in token_credentials:
        token_cred_format = c.get(TOKEN_FORMAT_FIELD)
        if token_cred_format == MSO_MDOC_FORMAT:
            credentials.append(DcqlMdocCredential.model_validate(c))
        else:
            raise ValueError(f"Unknown credential format: {token_cred_format}")
    return credentials
