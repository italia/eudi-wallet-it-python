class NoBoundEndpointError(Exception):
    """
    Raised when a given url path is not bound to any endpoint function
    """


class NotTrustedFederationError(Exception):
    pass

class DPOPValidationError(Exception):
    """
    Raised when a DPoP validation error occurs
    """
    pass