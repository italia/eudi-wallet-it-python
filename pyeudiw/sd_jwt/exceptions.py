class UnknownCurveNistName(Exception):
    pass


class InvalidKeyBinding(Exception):
    pass


class UnsupportedSdAlg(Exception):
    pass


class SDJWTHasSDClaimException(Exception):
    """Exception raised when input data contains the special _sd claim reserved for SD-JWT internal data."""

    def __init__(self, error_location: any):
        super().__init__(
            f"Input data contains the special claim '{SD_DIGESTS_KEY}' reserved for SD-JWT internal data. Location: {error_location!r}"
        )
