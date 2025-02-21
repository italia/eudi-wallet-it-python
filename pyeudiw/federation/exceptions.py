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


class MissingTrustAnchorPublicKey(Exception):
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


class TimeValidationError(Exception):
    pass


class KeyValidationError(Exception):
    pass


class InvalidChainError(Exception):
    pass


class ProtocolMetadataNotFound(Exception):
    pass


class InvalidEntityHeader(Exception):
    pass


class InvalidEntityStatementPayload(Exception):
    pass


class PolicyError(Exception):
    pass
