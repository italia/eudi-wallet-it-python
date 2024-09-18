class VpVerifier:
    """VpVerifier validates and verify vp tokens
    """

    def verify():
        """verify checks the validity of a vp token based on implementation policy.

        :raises InvalidVPToken: raised when verification fails
        """
        raise NotImplementedError

    def parse_digital_credential() -> dict:
        """parse_digital_credential extracts digitals cretentials from aa vp
        token. The credential might or might not be verified, based on
        implementer policy. To ensure verification, use the method verify()

        :returns: a dictionary of credential, where the dictionary key is the
        credential name and the dictionary value is the credential value
        """
        raise NotImplementedError

    def check_revocation_status():
        raise NotImplementedError
