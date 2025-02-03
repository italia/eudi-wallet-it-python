from abc import ABC, abstractmethod

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.okp import OKPKey
from cryptojwt.jwk.hmac import SYMKey

KeyLike = ECKey | RSAKey | OKPKey | SYMKey


class JwsSigner(ABC):
    """JwsSigner is an interface that declares that an oject is able to sign a set
    of token claims.
    """

    @abstractmethod
    def sign(self, header: dict, payload: dict) -> str:
        """
        Sign the given set of claim and payload. The interface provides no
        guarantee that the input header is fully preserved, not does it guarantee
        that some optional but usually found header such as 'typ' and 'kid'
        are present.

        However, implementer of this interface MUST include the parameter 'alg'
        on the signed output token header as claim 'alg' is mandatory by RFC7515.
        If no such action is possible, this function should raise an
        """
        raise NotImplementedError


class JwsVerifier(ABC):
    """JwsVerifier is an interface that declares that an object is able to verify
    a jwt.
    """

    @abstractmethod
    def verify(self, jws: str) -> dict:
        """
        Verify a jwt token. If successfull, return the verified payload

        :raises JWSVerificationError: if there is any verification error
            or if the signature is invalid.
        """
        raise NotImplementedError


class JwsSignerVerifier(JwsSigner, JwsVerifier):
    pass


class JweEncrypter(ABC):
    """JweEncrypter is an interface that declares that an object is able to
    encrypt a set on claims to a jwe
    """

    @abstractmethod
    def encrypt(self, payload: dict):
        raise NotImplementedError


class JweDecrypter(ABC):
    """JweDecrypter is an interface that declares that an object is able to
    decrypt a jwe
    """

    @abstractmethod
    def decrypt(self, jws: str):
        raise NotImplementedError


class JweEncrypterDescrypter(JweEncrypter, JweDecrypter):
    pass
