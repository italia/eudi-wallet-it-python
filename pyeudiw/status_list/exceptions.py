class PositionOutOfRangeError(Exception):
    """
    Exception raised when the position is out of range.
    """
    pass

class InvalidTokenFormatError(Exception):
    """
    Exception raised when the token type is invalid.
    """
    pass

class MissingStatusListUriError(Exception):
    """
    Exception raised when the status list URI is missing.
    """
    pass

class StatusListRetrievalError(Exception):
    """
    Exception raised when there is an error retrieving the status list.
    """
    pass