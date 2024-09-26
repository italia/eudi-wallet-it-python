from dataclasses import dataclass

from sd_jwt.verifier import SDJWTVerifier

from pyeudiw.openid4vp.vp_sd_jwt_kb import VerifierChallenge
from pyeudiw.trust.interface import IssuerTrustModel


class IdeaVpVerifier:
    def get_verified_credential(self, token: str) -> dict:
        raise NotImplementedError

    # def get_issuer(self, token: str) -> dict:
    #     raise NotImplementedError


@dataclass
class IdeaNuovoVpVerifier(IdeaVpVerifier):
    trust_model: IssuerTrustModel
    challenge: VerifierChallenge

    def get_verified_credentials(self, vc_sdjwt: str) -> dict:
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
