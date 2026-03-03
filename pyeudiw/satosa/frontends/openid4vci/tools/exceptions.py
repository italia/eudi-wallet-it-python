class InvalidRequestException(Exception):
    """
    Exception raised when a request is invalid according to OpenID4VCI specifications.
    """

    def __init__(self, message: str):
        """
        Initializes the exception with a descriptive error message.

        Args:
            message (str): Description of the invalid request.
        """

        super().__init__(message)
        self.message = message


class MissingProofJWTException(Exception):
    """
    Raised when proof JWT is required but missing from the credential request.

    Attributes:
        message (str): A human-readable explanation.
    """

    def __init__(self, message: str = "missing proof JWT"):
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
