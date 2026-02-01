class PositionOutOfRangeError(Exception):
    """
    Exception raised when the position is out of range.
    """

class InvalidTokenFormatError(Exception):
    """
    Exception raised when the token type is invalid.
    """

class MissingStatusListUriError(Exception):
    """
    Exception raised when the status list URI is missing.
    """

class StatusListRetrievalError(Exception):
    """
    Exception raised when there is an error retrieving the status list.
    """
