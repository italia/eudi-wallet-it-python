def is_ec(payload: dict) -> None:
    """
    Determines if payload dict is an Entity Configuration

    :param payload: the object to determine if is an Entity Configuration
    :type payload: dict
    """

    try:
        EntityConfigurationPayload(**payload)
    except ValueError as e:
        _msg = f"Invalid Entity Configuration: {e}"
        raise InvalidEntityConfiguration(_msg)