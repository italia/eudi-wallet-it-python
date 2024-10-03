from pyeudiw.jwk import JWK
from pyeudiw.jwt.parse import KeyIdentifier_T


class VpTokenParser:
    """VpTokenParser is an interface that specify that an object is able to
    extract verifiable credentials from a VP token.
    """
    def get_credentials(self) -> dict:
        raise NotImplementedError

    def get_issuer_name(self) -> str:
        raise NotImplementedError

    def get_signing_key(self) -> dict | KeyIdentifier_T:
        """
        :returns: a public key either as a dictionary or as an identifier
            (kid string) of a public key as seen in header
        :rtype: dict | str
        """
        raise NotImplementedError


class VpTokenVerifier:
    """VpTokenVerifier is an interface that specify that an object is able to
    verify a vp token.
    The interface supposes that the verification process requires a public
    key (os the token issuer)
    """
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
        raise NotImplementedError

    # TODO: VP proof of possession verification method should be implemented
