class TrustEvaluator:
    """
    TrustEvaluator is an interface that defined the expected behaviour of a
    class that, as the very core, can:
    (1) obtain the cryptographic material of an issuer, which might or might
        not be trusted according to some trust model
    (2) obtain the meta information about an issuer that is defined
        according to some trust model
    """
    def initialize_istance(self, issuer: str) -> None:
        """
        Initialize the cryptographic material of the issuer, according to some
        trust model.
        """
        raise NotImplementedError

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        yields the public cryptographic material of the issuer

        :returns: a list of jwk(s); note that those key are _not_ necessarely
            identified by a kid claim
        """
        raise NotImplementedError

    def get_metadata(self, issuer: str) -> dict:
        """
        yields a dictionary of metadata about an issuer, according to some
        trust model.
        """
        raise NotImplementedError

    def is_revoked(self, issuer: str) -> bool:
        """
        yield if the trust toward the issuer was revoked according to some trust model;
        this asusmed that  the isser exists, is valid, but is not trusted.
        """
        raise NotImplementedError

    def get_policies(self, issuer: str) -> dict:
        raise NotImplementedError("reserved for future uses")
    
    def get_selfissued_jwt_header_trust_parameters(self) -> dict:
        raise NotImplementedError
