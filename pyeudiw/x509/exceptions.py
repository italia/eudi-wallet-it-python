class CRLHTTPError(Exception):
    """Exception raised for errors in the CRL HTTP request."""

class CRLParseError(Exception):
    """Exception raised for errors in parsing the CRL."""

class CRLReadError(Exception):
    """Exception raised for errors in reading the CRL."""
