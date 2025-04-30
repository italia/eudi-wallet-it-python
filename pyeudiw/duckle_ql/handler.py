import logging
from typing import Dict, Any

from pyeudiw.duckle_ql.attribute_mapper import extract_claims, flatten_namespace
from pyeudiw.duckle_ql.credential import CredentialsRequest
from pyeudiw.openid4vp.exceptions import InvalidVPToken
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser
from pyeudiw.openid4vp.vp_mdoc_cbor import VpMDocCbor
from pyeudiw.openid4vp.vp_sd_jwt_vc import VpVcSdJwtParserVerifier
from pyeudiw.presentation_definition.utils import DUCKLE_PRESENTATION, DUCKLE_QUERY_KEY
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

EXP_CLAIM = "exp"
SUB_CLAIM = "sub"
DECODE_OPT = {"verify_signature": False}
QUERY_CONFIG = "query"
CREDENTIALS = "credentials"
METADATA_JWKS_CONFIG_KEY = "metadata_jwks"

MSO_MDOC_FORMAT = "mso_mdoc"
VC_SD_JWT_FORMAT = "vc+sd-jwt"
DC_SD_JWT_FORMAT = "dc+sd-jwt"

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
        self.queries = CredentialsRequest.model_validate_json(kwargs.get(DUCKLE_PRESENTATION, {})[DUCKLE_QUERY_KEY])

    def parse(self,  token: dict) -> Dict[str, Any]:
        """
        Parse the Duckle Verifiable Presentation.

        :return: A dictionary representing the parsed presentation.
        :rtype: dict
        """
        all_claims = {}
        credentials = self.queries.credentials
        for cred in credentials:
            token_str = token[cred.id]
            try:
                paths = [{"path": claim.path} for claim in cred.claims]
                if cred.format == VC_SD_JWT_FORMAT or cred.format == DC_SD_JWT_FORMAT:
                    parser = VpVcSdJwtParserVerifier(self.trust_evaluator, self.sig_alg_supported)
                    data = parser.parse(token_str)
                elif cred.format == MSO_MDOC_FORMAT:
                    parser = VpMDocCbor(self.trust_evaluator)
                    data = flatten_namespace(parser.parse(token_str))
                else:
                    raise InvalidVPToken(f"Unexpected token format {cred.format}")

                all_claims.update(extract_claims(data, paths))

            except Exception as e:
                logging.exception(f"Error parsing token for credential {cred.id}")
                raise e
            return all_claims

    def validate(
        self,
        token: dict,
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
        :raises InvalidVPToken: If the signature or claims are invalid.
        """
        credentials = self.queries.credentials
        expected_ids = [credential.id for credential in credentials]
        missing_ids = [id_ for id_ in expected_ids if id_ not in token]
        if missing_ids:
            logging.error(f"Missing credential IDs in DCQL token: {missing_ids!r}")
            raise InvalidVPToken("Missing credential IDs in DCQL token")
        unexpected_id = [key for key in token if key not in expected_ids]
        if unexpected_id:
            logging.error(f"Unexpected credential IDs in DCQL token: {unexpected_id!r}")
            raise InvalidVPToken("Unexpected credential IDs in DCQL token")

        for cred in credentials:
            token_str = token[cred.id]
            try:
                if cred.format == VC_SD_JWT_FORMAT or cred.format == DC_SD_JWT_FORMAT:
                    parser = VpVcSdJwtParserVerifier(self.trust_evaluator, self.sig_alg_supported)
                elif cred.format == MSO_MDOC_FORMAT:
                    parser = VpMDocCbor(self.trust_evaluator)
                else:
                    raise InvalidVPToken(f"Unexpected token format {cred.format}")
                parser.validate(token_str, verifier_id, verifier_nonce)
            except Exception as e:
                    logging.exception(f"Error parsing token for credential '{cred.id}'")
                    raise e