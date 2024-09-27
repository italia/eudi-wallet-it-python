from dataclasses import dataclass
from typing import Optional

from jwcrypto.common import base64url_decode, json_decode
from sd_jwt.common import SDJWTCommon
from sd_jwt.verifier import SDJWTVerifier

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.schemas.jwt import UnverfiedJwt
from pyeudiw.jwt.utils import unsafe_parse_jws
from pyeudiw.openid4vp.vp_sd_jwt_kb import VerifierChallenge
from pyeudiw.sd_jwt.schema import is_sd_jwt_kb_format
from pyeudiw.tools.utils import iat_now
from pyeudiw.trust.interface import IssuerTrustEvaluator, TrustEvaluator


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

    def verify_signature(self, public_key: JWK) -> None:
        """
        :raises [InvalidSignatureException]:
        """
        return


class VpVcSdJwtParserVerifier(VpTokenParser, VpTokenVerifier):
    def __init__(self, sdjwtkb: str, verifier_id: Optional[str] = None, verifier_nonce: Optional[str] = None):
        self.sdjwtkb = sdjwtkb
        if not is_sd_jwt_kb_format(sdjwtkb):
            raise ValueError(f"input [sdjwtkb]={sdjwtkb} is not an sd-jwt with key binding: maybe it is a regular jwt or key binding jwt is missing?")
        self.verifier_id = verifier_id
        self.verifier_nonce = verifier_nonce
        # precomputed values
        self._issuer_jwt: UnverfiedJwt = UnverfiedJwt("", "", "", "")
        self._encoded_disclosures: list[str] = []
        self._disclosures: list[dict] = []
        self._kb_jwt: UnverfiedJwt = UnverfiedJwt("", "", "", "")
        self._post_init_evaluate_precomputed_values()

    def _post_init_evaluate_precomputed_values(self):
        iss_jwt, *disclosures, kb_jwt = self.sdjwtkb.split(SDJWTCommon.COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
        self._encoded_disclosures = disclosures
        self._disclosures = [json_decode(base64url_decode(disc)) for disc in disclosures]
        self._issuer_jwt = unsafe_parse_jws(iss_jwt)
        self._kb_jwt = unsafe_parse_jws(kb_jwt)

    def get_issuer_name(self) -> str:
        iss = self._issuer_jwt.payload.get("iss", None)
        if not iss:
            raise Exception("missing required information in token paylaod: [iss]")

    def get_credentials(self) -> dict:
        # TODO: fa un sacco di copia incolla da SDJWTVerifier
        raise NotImplementedError("TODO")

    def get_signing_key(self) -> dict | str:
        # TODO: usa SOLO l'header del token -> la parte di match è fatta FUORI dalla classe
        if (maybe_kid := self._issuer_jwt.header.get("kid", None)):
            return maybe_kid
        JWSHelper
        if (maybe_trust_chain := self._issuer_jwt.header.get("trust_chain", None)):
            return qualcosa che prende la chiave dalla trust chian
        # ??????
        pass

    def is_revoked(self) -> bool:
        return False

    def is_expired(self) -> bool:
        exp = self._issuer_jwt.payload.get("exp", None)
        if not exp:
            return True
        if exp < iat_now():
            return True
        return False

    def verify_signature(self, public_key: JWK) -> None:
        # TODO: usa questa PPK per fare la verifica delle public keys
        # ??????: fa la verifica del kb jwt? dove?
        


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
