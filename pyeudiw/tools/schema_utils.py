from pydantic_core.core_schema import ValidationInfo

_default_supported_algorithms = [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
]


def check_algorithm(alg: str, info: ValidationInfo) -> None:
    """
    Check if the algorithm is supported by the relaying party.

    :param alg: The algorithm to check
    :type alg: str
    :param info: The field validation info
    :type info: ValidationInfo

    :raises ValueError: If the algorithm is not supported
    """

    if not info.context:
        supported_algorithms = _default_supported_algorithms
    else:
        supported_algorithms = info.context.get(
            "supported_algorithms", _default_supported_algorithms)
    if not isinstance(supported_algorithms, list):
        supported_algorithms = []
    if alg not in supported_algorithms:
        raise ValueError(
            f"Unsupported algorithm: {alg}. "
            f"Supported algorithms: {supported_algorithms}."
        )
