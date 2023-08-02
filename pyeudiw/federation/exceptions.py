class HttpError(Exception):
    pass


class TrustChainHttpError(HttpError):
    pass


class UnknownKid(Exception):
    pass


class MissingJwksClaim(Exception):
    pass


class MissingAuthorityHintsClaim(Exception):
    pass


class NotDescendant(Exception):
    pass


class TrustAnchorNeeded(Exception):
    pass


class MetadataDiscoveryException(Exception):
    pass


class MissingTrustMark(Exception):
    pass


class InvalidRequiredTrustMark(Exception):
    pass


class InvalidTrustchain(Exception):
    pass


class TrustchainMissingMetadata(Exception):
    pass


class InvalidEntityConfiguration(Exception):
    pass


class InvalidEntityStatement(Exception):
    pass
