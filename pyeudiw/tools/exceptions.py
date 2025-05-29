class HttpError(Exception):
    pass

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


class InvalidScopeException(Exception):
    """
    Exception raised when a request contains an invalid or unsupported scope.
    Attributes:
        message (str): A human-readable explanation of the scope error.
    """

    def __init__(self, message: str):
        """
        Initializes the exception with a descriptive error message.
        Args:
            message (str): Description of the invalid scope.
        """
        super().__init__(message)
        self.message = message