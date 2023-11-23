from pyeudiw.federation.schemas.entity_configuration import EntityStatementPayload, EntityConfigurationPayload

def is_es(payload: dict) -> bool:
    try:
        EntityStatementPayload(**payload)
        if payload["iss"] != payload["sub"]:
            return True
    except Exception:
        return False


def is_ec(payload: dict) -> bool:
    try:
        EntityConfigurationPayload(**payload)
        return True
    except Exception as e:
        return False