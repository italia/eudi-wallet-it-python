from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey

from pyeudiw.jwt.helper import is_jwt_expired
from pyeudiw.sd_jwt.schema import VerifierChallenge
from pyeudiw.sd_jwt.sd_jwt import SdJwt
from pyeudiw.openid4vp.exceptions import MissingIssuer
from pyeudiw.openid4vp.exceptions import VPExpired
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

    def _get_credentials(self, sdjwt: SdJwt) -> dict:
        """
        Get the disclosed claims from the token payload.

        :raises ValueError: if there are multiple claims with the same digest
        :raises UnsupportedSdAlg: if the sd-jwt algorithm is not supported

        :return: the disclosed claims
        :rtype: dict
        """
        return sdjwt.get_disclosed_claims()
    
    def parse(self, token: str) -> dict:
        sdjwt = SdJwt(token)

        return self._get_credentials(sdjwt)

    def _is_revoked(self) -> bool:
        # TODO: implement revocation check
        return False

    def _is_expired(self, sdjwt: SdJwt) -> bool:
        """
        Check if the credential is expired.

        :returns: if the credential is expired
        :rtype: bool
        """
        return is_jwt_expired(sdjwt.issuer_jwt.jwt)
    
    def _verify_signature(self, sdjwt: SdJwt, public_keys: list[ECKey | RSAKey | dict] | None = None) -> None:
        """
        Verifies the signature of the jwt.

        :param public_key: the public key to verify the signature
        :type public_key: ECKey | RSAKey | dict

        :raises JWSVerificationError: if the signature is invalid
        """
        return sdjwt.verify_issuer_jwt_signature(public_keys)

    def _verify_challenge(self, sdjwt: SdJwt, verifier_id: str, verifier_nonce: str) -> None:
        """
        Verifies the challenge of the jwt.

        :raises UnsupportedSdAlg: if verification fails due to an unkown _sd_alg
        :raises InvalidKeyBinding: if the verification fails for a known reason
        :raises ValueError: if the iat claim is missing or invalid
        :raises JWSVerificationError: if the verification fails
        """

        challenge: VerifierChallenge = {}
        challenge["aud"] = verifier_id
        challenge["nonce"] = verifier_nonce

        sdjwt.verify_holder_kb_jwt(challenge)
    
    def validate(
        self, 
        token: str, 
        verifier_id: str, 
        verifier_nonce: str, 
    ) -> None:
        # precomputed values
        sdjwt = SdJwt(token)

        public_keys = self.trust_evaluator.get_public_keys(
            self._get_issuer_name(sdjwt)
        )

        self._verify_signature(sdjwt, public_keys)
        self._verify_challenge(sdjwt, verifier_id, verifier_nonce)

        if self._is_expired(sdjwt):
            raise VPExpired("VP is expired")
        
        # TODO: implement revocation check