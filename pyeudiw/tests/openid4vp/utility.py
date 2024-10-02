from pyeudiw.jwk import JWK
from pyeudiw.openid4vp.interface import VpTokenParser, VpTokenVerifier


class VpParserVoid(VpTokenParser):
    """Default implementation of VpTokenParser. This should be used only
    for mocking and testing purposes only.
    """
    def get_credentials(self) -> dict:
        return {}

    def get_issuer_name(self) -> str:
        return ""

    def get_signing_key(self) -> dict | str:
        """
        :returns: a public key or an identifier of a public key as seen in header
        """
        return ""


class VpVerifierVoid(VpTokenVerifier):
    """Default implementation of VpTokenVerifier. This should be used only
    for mocking and testing purposes only.
    """
    def is_expired(self) -> bool:
        return False

    def is_revoked(self) -> bool:
        return False

    def verify_signature(self, public_key: JWK) -> None:
        return


class VpParserVerifierVoid(VpParserVoid, VpVerifierVoid):
    """Default implementation of VpTokenParser and VpTokenVerifier. This should be
    used only for mocking and testing purposes only.
    The function always returnm "zero value" for all its methods.
    """
    pass
