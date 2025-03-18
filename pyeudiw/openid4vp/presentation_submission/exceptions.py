class MissingHandler(Exception):
    """
    Exception raised when a handler is missing.
    """
    pass

class MalformedPath(Exception):
    """
    Exception raised when a path inside the descriptor map is malformed.
    """
    pass

class SubmissionValidationError(Exception):
    """
    Exception raised when a submission is invalid.
    """
    pass

class VPTokenDescriptorMapMismatch(Exception):
    """
    Exception raised when the number of tokens does not match the number of descriptors.
    """
    pass