from typing import Optional

from pyeudiw.jwt.helper import JWSHelper
from pyeudiw.jwt.verification import is_jwt_expired
from pyeudiw.openid4vp.exceptions import InvalidVPKeyBinding
from pyeudiw.openid4vp.interface import VpTokenParser, VpTokenVerifier
from pyeudiw.sd_jwt.exceptions import InvalidKeyBinding, UnsupportedSdAlg
from pyeudiw.sd_jwt.schema import VerifierChallenge, is_sd_jwt_kb_format
from pyeudiw.sd_jwt.sd_jwt import SdJwt
from pyeudiw.trust.interface import TrustedPublicKeySource


class VpVcSdJwtParserVerifier(VpTokenParser, VpTokenVerifier):

    def __init__(self, token: str, verifying_keys: list[dict] | TrustedPublicKeySource,
                 verifier_id: Optional[str] = None, verifier_nonce: Optional[str] = None):
        self.token = token
        if not is_sd_jwt_kb_format(token):
            raise ValueError(f"input [token]={token} is not an sd-jwt with key binding: maybe it is a regular jwt or key binding jwt is missing?")
        self.verifier_id = verifier_id
        self.verifier_nonce = verifier_nonce
        # precomputed values
        self.sdjwt = SdJwt(self.token)
        _issuer_keys: list[dict] = []
        if hasattr(verifying_keys, 'get_public_keys'):
            # this IF is duck typing check on TrustEvaluator / TrustedPublicKeySource
            _issuer_keys = verifying_keys.get_public_keys(self.sdjwt.get_issuer_jwt())
        elif isinstance(verifying_keys, list):
            _issuer_keys = verifying_keys
        else:
            raise TypeError("unsupported type verifying_keys of: must either be list[dict] or implement method 'get_public_keys(issuer: str) -> list[dict]'")
        self._sdjwt_issuer_jwt_verifier = JWSHelper(_issuer_keys)

    def get_issuer_name(self) -> str:
        iss = self.sdjwt.issuer_jwt.payload.get("iss", None)
        if not iss:
            raise Exception("missing required information in token paylaod: [iss]")
        return iss

    def get_credentials(self) -> dict:
        return self.sdjwt.get_disclosed_claims()

    def is_revoked(self) -> bool:
        # TODO: implement revocation check
        return False

    def is_expired(self) -> bool:
        return is_jwt_expired(self.sdjwt.issuer_jwt)

    def verify_signature(self) -> None:
        self._sdjwt_issuer_jwt_verifier.verify(self.sdjwt.issuer_jwt)

    def verify_challenge(self) -> None:
        challenge: VerifierChallenge = {
            "aud": self.verifier_id,
            "nonce": self.verifier_nonce
        }
        try:
            self.sdjwt.verify_holder_kb_jwt(challenge)
        except (UnsupportedSdAlg, InvalidKeyBinding) as e:
            raise InvalidVPKeyBinding(f"{e}")
