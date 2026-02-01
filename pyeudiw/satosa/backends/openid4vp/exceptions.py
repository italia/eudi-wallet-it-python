class AuthRespParsingException(Exception):
    """Raised when the http request corresponding to an authorization response is malformed."""


class AuthRespValidationException(Exception):
    """Raised when the http request corresponding to an authorization response is well formed,
    but not valid (for example, it might be wrapped in an expired token).
    """


class InvalidVPToken(Exception):
    """
    Raised when a given VP is invalid
    """

class VPFormatNotSupported(Exception):
    """
    Raised when a given VP format is not supported
    """

class NotKBJWT(Exception):
    """
    Raised when a given VP format is not Key Binding JWT format
    """

class MissingIssuer(Exception):
    """
    Raised when a given VP not contain the issuer
    """

class MdocCborValidationError(Exception):
    """
    Raised when a given VP not contain the issuer
    """

class VPExpired(Exception):
    """
    Raised when a given VP is expired
    """

class VPRevoked(Exception):
    """
    Raised when a given VP is revoked
    """
