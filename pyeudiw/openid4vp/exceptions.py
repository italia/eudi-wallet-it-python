class KIDNotFound(Exception):
    """
    Raised when kid is not present in the public key dict
    """


class VPNotFound(Exception):
    pass


class VPInvalidNonce(Exception):
    pass


class NoNonceInVPToken(Exception):
    """
    Raised when a given VP has no nonce
    """


class InvalidVPToken(Exception):
    """
    Raised when a given VP is invalid
    """
