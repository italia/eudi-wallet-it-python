from pyeudiw.exceptions import ValidationError


class JWEDecryptionError(Exception):
    pass

class JWTInvalidElementPosition(Exception):
    pass


class JWSSigningError(Exception):
    pass


class JWSVerificationError(Exception):
    pass


class JWEEncryptionError(Exception):
    pass


class JWTDecodeError(Exception):
    pass


class LifetimeException(ValidationError):
    """Exception raised for errors related to lifetime validation."""
    pass
