class MissingHandler(Exception):
    """
    Exception raised when a handler is missing.
    """


class MalformedPath(Exception):
    """
    Exception raised when a path inside the descriptor map is malformed.
    """


class SubmissionValidationError(Exception):
    """
    Exception raised when a submission is invalid.
    """


class VPTokenDescriptorMapMismatch(Exception):
    """
    Exception raised when the number of tokens does not match the number of descriptors.
    """


class ParseError(Exception):
    """
    Exception raised when parsing fails.
    """


class ValidationError(Exception):
    """
    Exception raised when parsing fails.
    """
