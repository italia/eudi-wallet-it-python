from typing import Optional

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey

from pyeudiw.jwt.helper import is_jwt_expired
from pyeudiw.openid4vp.interface import VpTokenParser, VpTokenVerifier
from pyeudiw.sd_jwt.schema import VerifierChallenge
from pyeudiw.sd_jwt.sd_jwt import SdJwt
from pyeudiw.openid4vp.exceptions import NotKBJWT, MissingIssuer


class VpVcSdJwtParserVerifier(VpTokenParser, VpTokenVerifier):
    def __init__(
        self,
        token: str,
        verifier_id: Optional[str] = None,
        verifier_nonce: Optional[str] = None,
    ):
        self.token = token
        self.verifier_id = verifier_id
        self.verifier_nonce = verifier_nonce
        # precomputed values
        self.sdjwt = SdJwt(self.token)

    def get_issuer_name(self) -> str:
        """
        Get the issuer name from the token payload.

        :raises MissingIssuer: if the issuer name is missing in the token payload

        :return: the issuer name
        :rtype: str
        """
        iss = self.sdjwt.get_issuer_jwt().payload.get("iss", None)
        if not iss:
            raise MissingIssuer("missing required information in token paylaod: [iss]")
        return iss

    def get_credentials(self) -> dict:
        """
        Get the disclosed claims from the token payload.

        :raises ValueError: if there are multiple claims with the same digest
        :raises UnsupportedSdAlg: if the sd-jwt algorithm is not supported

        :return: the disclosed claims
        :rtype: dict
        """
        return self.sdjwt.get_disclosed_claims()

    def is_revoked(self) -> bool:
        # TODO: implement revocation check
        return False

    def is_expired(self) -> bool:
        """
        Check if the credential is expired.

        :returns: if the credential is expired
        :rtype: bool
        """
        return is_jwt_expired(self.sdjwt.issuer_jwt)

    def verify_signature(self, public_key: ECKey | RSAKey | dict) -> None:
        """
        Verifies the signature of the jwt.

        :param public_key: the public key to verify the signature
        :type public_key: ECKey | RSAKey | dict

        :raises JWSVerificationError: if the signature is invalid
        """
        return self.sdjwt.verify_issuer_jwt_signature(public_key)

    def verify_challenge(self) -> None:
        """
        Verifies the challenge of the jwt.

        :raises UnsupportedSdAlg: if verification fails due to an unkown _sd_alg
        :raises InvalidKeyBinding: if the verification fails for a known reason
        :raises ValueError: if the iat claim is missing or invalid
        :raises JWSVerificationError: if the verification fails
        """

        challenge: VerifierChallenge = {}
        challenge["aud"] = self.verifier_id
        challenge["nonce"] = self.verifier_nonce

        self.sdjwt.verify_holder_kb_jwt(challenge)