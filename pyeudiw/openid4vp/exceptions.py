class AuthRespParsingException(Exception):
    """Raised when the http request corresponding to an authorization response is malformed."""
    pass


class AuthRespValidationException(Exception):
    """Raised when the http request corresponding to an authorization response is well formed,
    but not valid (for example, it might be wrapped in an expired token).
    """
    pass


class InvalidVPToken(Exception):
    """
    Raised when a given VP is invalid
    """
    pass

class VPFormatNotSupported(Exception):
    """
    Raised when a given VP format is not supported
    """
    pass

class NotKBJWT(Exception):
    """
    Raised when a given VP format is not Key Binding JWT format
    """
    pass

class MissingIssuer(Exception):
    """
    Raised when a given VP not contain the issuer
    """
    pass