import logging
from pyeudiw.jwt.helper import is_jwt_expired
from pyeudiw.sd_jwt.schema import VerifierChallenge
from pyeudiw.sd_jwt.sd_jwt import SdJwt
from pyeudiw.openid4vp.exceptions import MissingIssuer, VPRevoked, VPExpired
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.sd_jwt.schema import is_sd_jwt_kb_format
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.status_list.helper import StatusListTokenHelper

class VpVcSdJwtParserVerifier(BaseVPParser):

    def __init__(self, trust_evaluator: CombinedTrustEvaluator, sig_alg_supported: list[str] = [], **kwargs) -> None:
        """
        Initialize the VpVcSdJwtParserVerifier with the trust evaluator.

        :param trust_evaluator: The trust evaluator instance.
        :type trust_evaluator: CombinedTrustEvaluator
        :param sig_alg_supported: List of supported signature algorithms.
        :type sig_alg_supported: list[str]
        """
        self.sig_alg_supported = sig_alg_supported
        super().__init__(trust_evaluator, **kwargs)

    def _get_issuer_name(self, sdjwt: SdJwt) -> str:
        """
        Get the issuer name from the token payload.

        :raises MissingIssuer: if the issuer name is missing in the token payload

        :return: the issuer name
        :rtype: str
        """
        iss = sdjwt.get_issuer_jwt().payload.get("iss", None)
        if not iss:
            raise MissingIssuer("missing required information in token paylaod: [iss]")
        return iss
    
    def parse(self, token: str) -> dict:
        sdjwt = SdJwt(token)

        return sdjwt.get_disclosed_claims()

    def _is_revoked(self) -> bool:
        # TODO: implement revocation check
        return False
    
    def validate(
        self, 
        token: str, 
        verifier_id: str, 
        verifier_nonce: str, 
    ) -> None:
        # precomputed values
        if not is_sd_jwt_kb_format(token):
            raise ValueError("Token is not in the expected format")

        sdjwt = SdJwt(token)

        static_trust_materials = {}
        header = decode_jwt_header(token)

        alg = header.get("alg", None)
        if alg not in self.sig_alg_supported:
            raise ValueError(f"Unsupported algorithm: {alg}")

        if "x5c" in header:
            static_trust_materials["x5c"] = header["x5c"]
        
        if "trust_chain" in header:
            static_trust_materials["trust_chain"] = header["trust_chain"]
        
        public_keys = self.trust_evaluator.get_public_keys(
            self._get_issuer_name(sdjwt),
            static_trust_materials
        )

        sdjwt.verify_issuer_jwt_signature(public_keys)
        
        challenge: VerifierChallenge = {}
        challenge["aud"] = verifier_id
        challenge["nonce"] = verifier_nonce

        sdjwt.verify_holder_kb_jwt(challenge)

        if is_jwt_expired(sdjwt.issuer_jwt.jwt):
            raise VPExpired("VP is expired")
        
        payload = decode_jwt_payload(token)

        if "status" in payload:
            status_list = StatusListTokenHelper.from_status(payload["status"])
            if status_list.is_expired() or \
               status_list.get_status(payload["status"]["status_list"]["idx"]) > 0:
                raise VPRevoked(
                    "Status list indicates that the token is revoked"
                )