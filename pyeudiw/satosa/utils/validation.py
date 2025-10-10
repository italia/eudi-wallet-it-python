import logging
from typing import Optional

from cryptojwt.jwk.jwk import key_from_jwk_dict
from satosa.context import Context

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.tools.content_type import (
    FORM_URLENCODED,
    APPLICATION_JSON,
    is_form_urlencoded,
    is_application_json
)

OAUTH_CLIENT_ATTESTATION_POP_HEADER = "HTTP_OAUTH_CLIENT_ATTESTATION_POP"
OAUTH_CLIENT_ATTESTATION_HEADER = "HTTP_OAUTH_CLIENT_ATTESTATION"

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

def validate_client_attestation(wallet_attestation:str, signing_alg_values_supported: list[str] | None) -> Optional[dict]:
    """
    Validates the Wallet Attestation JWT and extracts the confirmation method.
    :param wallet_attestation: as Wallet Attestation JWT.
    :param signing_alg_values_supported: as list of accepted signing algorithms.
    :return: validated attestation info or None if not present.
    """
    if wallet_attestation:
        payload = decode_jwt_payload(wallet_attestation)
        cnf = payload["cnf"]
        jws_helper = JWSHelper(cnf)

        if signing_alg_values_supported and jws_helper.jwks[0].alg not in signing_alg_values_supported:
            raise InvalidRequestException(
                f"Unsupported JWS algorithm: {jws_helper.jwks[0].alg}. Supported algorithms: {signing_alg_values_supported}")

        jws_helper.verify(wallet_attestation)

        return {
            "thumbprint": str(key_from_jwk_dict(cnf).thumbprint("SHA-256"))
        }
    return None

def validate_oauth_client_attestation_pop(context: Context, dpop_signing_alg_values_supported: list[str] | None = None) -> None:
    """
    Validates the presence of the OAuth-Client-Attestation-PoP header in the request.
    Args:
        :param context: (Context) The SATOSA context containing the HTTP request.
        :param dpop_signing_alg_values_supported: as list of accepted DPoP signing algorithms.
            May be empty.
    Raises:
        InvalidRequestException: If the OAuth-Client-Attestation-PoP header is missing.
    """
    header_pop = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER)

    if not header_pop:
        logger.error(f"Missing {OAUTH_CLIENT_ATTESTATION_POP_HEADER} header")
        raise InvalidRequestException("Missing OAuth-Client-Attestation-PoP header")

    if dpop_signing_alg_values_supported:
        try:
            validate_client_attestation(header_pop, dpop_signing_alg_values_supported)
        except Exception as e:
            logger.error(
                f"{'JWS verification failed' if isinstance(e, JWSVerificationError) else 'Unexpected error'} "
                f"during {OAUTH_CLIENT_ATTESTATION_POP_HEADER} header validation: {e}"
            )
            raise InvalidRequestException("Invalid Wallet Attestation JWT header")

def validate_oauth_client_attestation(context: Context, pop_signing_alg_values_supported: list[str] | None) -> Optional[dict]:
    """
    Validates the presence and correctness of OAuth-Client-Attestation headers in the request.

    This function checks that the `OAuth-Client-Attestation` and
    `OAuth-Client-Attestation-PoP` headers are present in the incoming HTTP request
    and verifies their cryptographic validity according to the
    Attestation-based Client Authentication specification. It also validates
    the DPoP proof using the provided list of supported signing algorithms.

    Args:
        :param context: (Context) The SATOSA context containing the HTTP request.
        :param pop_signing_alg_values_supported: (list[str]): A list of accepted DPoP signing algorithms.
            May be empty if DPoP is not required.

    Returns:
        Optional[dict]: A dictionary containing client attestation information if verification succeeds;
        None if attestation is not required and not present.

    Raises:
        InvalidRequestException: If any required header is missing, malformed, or fails verification.
    """
    header_attestation = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER)
    
    if not header_attestation:
        logger.error(f"Missing {OAUTH_CLIENT_ATTESTATION_HEADER} header")
        raise InvalidRequestException("Missing Wallet Attestation JWT header")
    
    try:
        return validate_client_attestation(header_attestation, pop_signing_alg_values_supported)
    except Exception as e:
        logger.error(
            f"{'JWS verification failed' if isinstance(e, JWSVerificationError) else 'Unexpected error'} "
            f"during {OAUTH_CLIENT_ATTESTATION_HEADER} header validation: {e}"
        )
        raise InvalidRequestException("Invalid Wallet Attestation JWT header")

