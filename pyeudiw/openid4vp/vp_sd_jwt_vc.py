from pyeudiw.jwt.helper import is_jwt_expired
from pyeudiw.sd_jwt.schema import VerifierChallenge
from pyeudiw.sd_jwt.sd_jwt import SdJwt
from pyeudiw.openid4vp.exceptions import MissingIssuer
from pyeudiw.openid4vp.exceptions import VPExpired
from pyeudiw.sd_jwt.schema import is_sd_jwt_kb_format
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser


class VpVcSdJwtParserVerifier(BaseVPParser):
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

        public_keys = self.trust_evaluator.get_public_keys(
            self._get_issuer_name(sdjwt)
        )

        sdjwt.verify_issuer_jwt_signature(public_keys)
        
        challenge: VerifierChallenge = {}
        challenge["aud"] = verifier_id
        challenge["nonce"] = verifier_nonce

        sdjwt.verify_holder_kb_jwt(challenge)

        if is_jwt_expired(sdjwt.issuer_jwt.jwt):
            raise VPExpired("VP is expired")
        
        # TODO: implement revocation check