class NoTrustChainProvided(Exception):
    pass


class UnknownTrustAnchor(Exception):
    pass


class MissingProtocolSpecificJwks(Exception):
    pass


class MissingTrustType(Exception):
    pass


class InvalidTrustType(Exception):
    pass


class InvalidAnchor(Exception):
    pass


class TrustConfigurationError(Exception):
    pass

class NoCriptographicMaterial(Exception):
    pass