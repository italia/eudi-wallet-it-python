class BadRequestError(Exception):
    """
    Bad Request error.

    This exception should be raised when we want to return an HTTP 400 Bad Request
    """


class InternalServerError(Exception):
    """
    Bad Request error.

    This exception should be raised when we want to return an HTTP 400 Bad Request
    """


class InvalidInternalStateError(InternalServerError):
    """
    This is specification of InternalServerError that specify that the internal
    error is caused by an invalid backend, storage or cache state.
    """


class FinalizedSessionError(BadRequestError):
    """
    Raised when an authorization request or respsonse attempts at updating or modifying
    an already finalized authentication session.
    """


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


class AuthorizeUnmatchedResponse(Exception):
    """
    Raised when an authorization response cannot be matched to an authentication request
    """

class InvalidRequestException(Exception):
    """
    Exception raised when a request is invalid according to OpenID4VCI specifications.

    Attributes:
        message (str): A human-readable explanation of why the request is invalid.
    """

    def __init__(self, message: str):
        """
        Initializes the exception with a descriptive error message.
        Args:
            message (str): Description of the invalid request.
        """
        super().__init__(message)
        self.message = message