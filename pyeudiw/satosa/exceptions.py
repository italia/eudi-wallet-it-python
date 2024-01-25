class BadRequestError(Exception):
    """
    Bad Request error.

    This exception should be raised when we want to return an HTTP 400 Bad Request
    """


class NoBoundEndpointError(Exception):
    """
    Raised when a given url path is not bound to any endpoint function
    """


class NotTrustedFederationError(Exception):
    pass


class DiscoveryFailedError(Exception):
    """
    Raised when the discovery fails
    """


class HTTPError(Exception):
    """
    Raised when an error occurs during an HTTP request
    """


class EmptyHTTPError(HTTPError):
    """
    Default HTTP empty error
    """


class DPOPValidationError(Exception):
    """
    Raised when a DPoP validation error occurs
    """
