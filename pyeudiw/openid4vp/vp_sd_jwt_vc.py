from typing import Optional

from pyeudiw.jwk import JWK
from pyeudiw.jwt.parse import KeyIdentifier_T, extract_key_identifier
from pyeudiw.jwt.verification import is_jwt_expired
from pyeudiw.openid4vp.interface import VpTokenParser, VpTokenVerifier
from pyeudiw.sd_jwt.schema import is_sd_jwt_kb_format
from pyeudiw.sd_jwt.sd_jwt import SdJwt


class VpVcSdJwtParserVerifier(VpTokenParser, VpTokenVerifier):
    def __init__(self, token: str, verifier_id: Optional[str] = None, verifier_nonce: Optional[str] = None):
        self.token = token
        if not is_sd_jwt_kb_format(token):
            raise ValueError(f"input [token]={token} is not an sd-jwt with key binding: maybe it is a regular jwt or key binding jwt is missing?")
        self.verifier_id = verifier_id
        self.verifier_nonce = verifier_nonce
        # precomputed values
        self.sdjwt = SdJwt(self.token)

    def get_issuer_name(self) -> str:
        iss = self.sdjwt.issuer_jwt.payload.get("iss", None)
        if not iss:
            raise Exception("missing required information in token paylaod: [iss]")

    def get_credentials(self) -> dict:
        return self.sdjwt.get_disclosed_claims()

    def get_signing_key(self) -> JWK | KeyIdentifier_T:
        return extract_key_identifier(self.sdjwt.issuer_jwt.header)

    def is_revoked(self) -> bool:
        return False

    def is_expired(self) -> bool:
        return is_jwt_expired(self.sdjwt.issuer_jwt)

    def verify_signature(self, public_key: JWK) -> None:
        return self.sdjwt.verify_issuer_jwt(public_key)
