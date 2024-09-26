from dataclasses import dataclass

from sd_jwt.verifier import SDJWTVerifier

from pyeudiw.openid4vp.vp_sd_jwt_kb import VerifierChallenge
from pyeudiw.trust.interface import IssuerTrustEvaluator


class VpTokenParser:
    def get_credentials(self) -> dict:
        raise NotImplementedError

    def get_issuer_name(self) -> str:
        raise NotImplementedError

    def get_signing_key(self) -> dict | str:
        """
        :returns: a public key or an identifier of a public key as seen in header
        """
        raise NotImplementedError


class VpTokenVerifier:
    def is_expired(self) -> bool:
        raise NotImplementedError

    def is_revoked(self) -> bool:
        """
        :returns: if the credential is revoked
        """
        raise NotImplementedError

    def is_active(self) -> bool:
        return (not self.is_expired()) and (not self.is_revoked())

    def verify_signature(self) -> None:
        """
        :raises [InvalidSignatureException]:
        """
        return


@dataclass
class IdeaNuovoVpVerifier(VpTokenVerifier):
    trust_model: IssuerTrustEvaluator
    challenge: VerifierChallenge

    def get_credentials(self, vc_sdjwt: str) -> dict:
        # implementazione minimale
        verifier = SDJWTVerifier(
            vc_sdjwt,
            self.trust_model.get_verified_key,
            self.challenge.aud,
            self.challenge.nonce
        )
        return verifier.get_verified_payload()


class EmptyVpVerifier:
    def get_verified_credential(self, token: str) -> dict:
        return {}
