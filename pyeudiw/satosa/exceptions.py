class BadRequestError(Exception):
    """
    Bad Request error.

    This exception should be raised when we want to return an HTTP 400 Bad Request
    """


class NoBoundEndpointError(Exception):
    """
    Raised when a given url path is not bound to any endpoint function
    """


class NoNonceInVPToken(Exception):
    """
    Raised when a given VP has no nonce
    """


class InvalidVPToken(Exception):
    """
    Raised when a given VP is invalid
    """


class NotTrustedFederationError(Exception):
    pass
