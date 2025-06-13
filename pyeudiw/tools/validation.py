import logging
import uuid

from satosa.context import Context

from pyeudiw.tools.content_type import (
    FORM_URLENCODED,
    APPLICATION_JSON,
    is_form_urlencoded,
    is_application_json
)
from pyeudiw.tools.exceptions import InvalidRequestException

OAUTH_CLIENT_ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP"
OAUTH_CLIENT_ATTESTATION_HEADER = "OAuth-Client-Attestation"

logger = logging.getLogger(__name__)


def validate_content_type(content_type_header: str, accepted_content_type: str):
    """
    Validate the Content-Type header against expected value.
    Args:
        content_type_header (str): The received Content-Type header.
        accepted_content_type (str): The expected value.
    Raises:
        InvalidRequestException: If the header does not match.
    """
    if (accepted_content_type == FORM_URLENCODED
            and not is_form_urlencoded(content_type_header)):
        logger.error(f"Invalid content-type for check `{FORM_URLENCODED}`: {content_type_header}")
        raise InvalidRequestException("invalid content-type")
    elif (accepted_content_type == APPLICATION_JSON
          and not is_application_json(content_type_header)):
        logger.error(f"Invalid content-type for check `{APPLICATION_JSON}`: {content_type_header}")
        raise InvalidRequestException("invalid content-type")

def validate_request_method(request_method: str, accepted_methods: list[str]):
    """
    Validate that the HTTP method is allowed.
    Args:
        request_method (str): The HTTP method.
        accepted_methods (list[str]): Allowed methods.
    Raises:
        InvalidRequestException: If the method is invalid.
    """
    if request_method is None or request_method.upper() not in accepted_methods:
        logger.error(f"endpoint invoked with wrong request method: {request_method}")
        raise InvalidRequestException("invalid request method")

def validate_oauth_client_attestation(context: Context):
    """
    Validate that OAuth-Client-Attestation headers are present.
    Args:
        context (Context): The SATOSA context.
    Raises:
        InvalidRequestException: If required headers are missing.
    """
    header_attestation = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER)
    header_pop = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER)
    if not header_attestation or not header_pop:
        header_value = OAUTH_CLIENT_ATTESTATION_HEADER if not header_attestation else OAUTH_CLIENT_ATTESTATION_POP_HEADER
        logger.error(f"Missing r{header_value} header for `par` endpoint")
        raise InvalidRequestException("Missing Wallet Attestation JWT header")

def is_valid_uuid(value: str) -> bool:
    """
    Method that check if given str is a valid uuid
    :param value: string to validate as uuid
    :return: validation result
    """
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError):
        return False