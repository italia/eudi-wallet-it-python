from pyeudiw.federation.schemas.entity_configuration import EntityStatementPayload, EntityConfigurationPayload

def is_es(payload: dict) -> bool:
    """
    Determines if payload dict is an Entity Statement

    :param payload: the object to determine if is an Entity Statement
    :type payload: dict

    :returns: True if is an Entity Statement and False otherwise
    :rtype: bool
    """

    try:
        EntityStatementPayload(**payload)
        if payload["iss"] != payload["sub"]:
            return True
    except Exception:
        return False


def is_ec(payload: dict) -> bool:
    """
    Determines if payload dict is an Entity Configuration

    :param payload: the object to determine if is an Entity Configuration
    :type payload: dict

    :returns: True if is an Entity Configuration and False otherwise
    :rtype: bool
    """

    try:
        EntityConfigurationPayload(**payload)
        return True
    except Exception as e:
        return False