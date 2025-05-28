class CRLHTTPError(Exception):
    """Exception raised for errors in the CRL HTTP request."""
    pass

class CRLParseError(Exception):
    """Exception raised for errors in parsing the CRL."""
    pass

class CRLReadError(Exception):
    """Exception raised for errors in reading the CRL."""
    pass