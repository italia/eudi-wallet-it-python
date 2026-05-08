import inspect
import logging

from pyeudiw.storage.credential_storage import CredentialEntity
from pyeudiw.satosa.frontends.openid4vci.storage.entity import AuthorizationSession

logger = logging.getLogger(__name__)


def __parse_credential_entity(credential_entity: dict) -> CredentialEntity:
    """
    Parse the credential entity from dictionary.
    """
    logger.debug(
        f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
        f"Params [credential_entity: {credential_entity}]"
    )
    print(
        f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
        f"Params [credential_entity: {credential_entity}]"
    )

    try:
        if not isinstance(credential_entity, dict):
            raise ValueError("Credential entity must be a dictionary.")

        return CredentialEntity(**credential_entity)

    except Exception as e:
        logger.error(
            f"Error parsing credential entity in "
            f"{inspect.currentframe().f_code.co_name}: {str(e)}"
        )
        raise ValueError("Invalid credential entity format.") from e


def parse_credential_entity(
    user_id: str,
    credential_type: str,
    auth_session: AuthorizationSession
) -> CredentialEntity:

    """
    Parse the credential entity from the authorization session and provided parameters.
    """
    logger.debug(
        f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
        f"Params [user_id: {user_id}, credential_type: {credential_type}]"
    )
    print(
        f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
        f"Params [user_id: {user_id}, credential_type: {credential_type}]"
    )

    credential_data = {
        "user_id": user_id,
        "credential_type": credential_type,
        "identifier": auth_session.authorization_details[0].credential_identifiers[0],
        "document_id": auth_session.document_id,
        "creation_date": auth_session.creation_date,
        "type":auth_session.authorization_details[0].type,
        "credential_id": auth_session.authorization_details[0].credential_configuration_id,
    }

    logger.debug(f"credential_data: {credential_data}")
    print(f"credential_data: {credential_data}")

    return __parse_credential_entity(credential_data)