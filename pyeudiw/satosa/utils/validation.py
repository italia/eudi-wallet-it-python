import logging
from typing import Optional

from cryptojwt.jwk.jwk import key_from_jwk_dict

from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.wallet_attestations import WalletInstanceAttestationHeader, WalletInstanceAttestationPayload

from pyeudiw.jwt.exceptions import JWSVerificationError, JWTInvalidElementPosition, JWTDecodeError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload, decode_jwt_header
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.tools.content_type import (
    APPLICATION_JSON,
    FORM_URLENCODED,
    is_application_json,
    is_form_urlencoded,
)

#todo move constants
OAUTH_CLIENT_ATTESTATION_POP_HEADER = "HTTP_OAUTH_CLIENT_ATTESTATION_POP"
OAUTH_CLIENT_ATTESTATION_HEADER = "HTTP_OAUTH_CLIENT_ATTESTATION"
DPOP_HEADER = "HTTP_DPOP"
METADATA_TYPE_WALLET_PROVIDER = "wallet_solution"

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
    if accepted_content_type == FORM_URLENCODED and not is_form_urlencoded(
        content_type_header
    ):
        logger.error(
            f"Invalid content-type for check `{FORM_URLENCODED}`: {content_type_header}"
        )
        raise InvalidRequestException("invalid content-type")
    elif accepted_content_type == APPLICATION_JSON and not is_application_json(
        content_type_header
    ):
        logger.error(
            f"Invalid content-type for check `{APPLICATION_JSON}`: {content_type_header}"
        )
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


def validate_jws(jws: str, sign_jwks: dict|list[dict], supported_sign_algs: list[str]|None = None) -> bool:
    """
    Validates JWS signature and algorithm against a whitelist.

    Args:
        jws: JWS in compact serialization.
        sign_jwks: Public JWKs for verification. If the list contains multiple values the choice of the key will be according to the logic of the class JWSHelper
        supported_sign_algs: List of allowed signing algorithms.

    Returns:
        boolean True if is valid or False otherwise.
    """
    try:
        if not jws or not sign_jwks:
            logger.error("Input parameter jws or sign_jwk is empty")
            return False

        supported_sign_algs = [] if supported_sign_algs is None else supported_sign_algs

        jws_helper = JWSHelper(sign_jwks)
        header = decode_jwt_header(jws)
        signing_alg = header.get("alg")
        if not supported_sign_algs:
            logger.warning("No supported signing algorithms whitelist provided")
        elif signing_alg not in supported_sign_algs:
            logger.error("Unsupported JWS signing algorithm")
        else:
            jws_helper.verify(jws)
            return True

    except (JWTInvalidElementPosition, JWTDecodeError) as e:
        logger.error("Cannot decode JWS, error: %s".format(e))
    except JWSVerificationError as e:
        logger.error("An error occurring while try to verify JWS: %s".format(e))
    except Exception as e:
        logger.error("An error occurred: %s".format(e))
    return False


def validate_subject_trust_chain(subject_url: str, authority_hints: list, httpc_params: dict) -> dict|None:
    """
    Validate subject trust chain and return it entity configuration

    Args:
        subject_url (str): url of federation subject.
        authority_hints (list): List of supported authority hints.
        httpc_params (dict): httpc params.

    Returns: issuer entity configuration or None
    """

    if not authority_hints or not subject_url:
        logger.error("Input parameter subject or authority_hints is empty")
        return None

    for _authority in authority_hints:
        _builder = TrustChainBuilder(subject_url, _authority, httpc_params)
        _builder.start()
        if _builder.is_valid:
            logger.info("Trust chain as been validated")
            return _builder.subject_configuration.payload
    logger.error("Invalid Trust Chain")
    return None

def validate_oauth_client_attestation_pop(client_attestation_pop: str,
                                          cnf_jwk: dict, signing_alg_values_supported: list[str] | None = None) -> dict:
    """
    Decodes and validates OAuth-Client-Attestation-PoP.

    Args:
        client_attestation_pop (str): JWS string.
        authority_hints (list): List of supported authority hints.
        httpc_params (dict): HTTP parameters.JWK
        cnf_jwk: signing public key as jwk.
        signing_alg_values_supported (list): List of supported signing algorithm values.

    Returns:
        dict: OAuth-Client-Attestation-PoP as decoded JWT payload.

    Raises: InvalidRequestException: If validation fails.

    References:
        - OAuth 2.0 Attestation-Based Client Authentication: https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/07/
    """

    if not client_attestation_pop:
        logger.error(f"Invalid OAuth-Client-Attestation-PoP")
        raise InvalidRequestException("JWS validation failed: invalid OAuth-Client-Attestation-PoP")

    try: #decode and validate header & payload of attestation
        attestation_jwt_header = decode_jwt_header(client_attestation_pop)
        attestation_jwt_payload = decode_jwt_payload(client_attestation_pop)
        #todo define and validate with basemodel
    except Exception as exc:
        logger.error("Invalid OAuth-Client-Attestation-PoP: %s", exc)
        raise InvalidRequestException("JWT validation failed: OAuth-Client-Attestation-PoP invalid structure") from exc

    if not validate_jws(client_attestation_pop, cnf_jwk, signing_alg_values_supported):
        raise InvalidRequestException("JWS verification failed: invalid OAuth-Client-Attestation-PoP")

    # references: - Page 8 (Version 07) of OAuth 2.0 Attestation-Based Client Authentication in docstring
    if attestation_jwt_payload.get("iss") != key_from_jwk_dict(cnf_jwk).thumbprint("SHA-256").decode(): #thumbprint is equivalent to sub claim in Client Attestation JWT.
        raise InvalidRequestException("OAuth-Client-Attestation-PoP verification failed: invalid iss value")
    return attestation_jwt_payload


def validate_oauth_client_attestation(client_attestation: str, authority_hints: list, httpc_params: dict,
                                      signing_alg_values_supported: list[str] | None = None) -> Optional[dict]:
    """
    Decodes and validates OAuth-Client-Attestation.

    Args:
        client_attestation (str): JWS string.
        authority_hints (list): List of supported authority hints.
        httpc_params (dict): HTTP parameters.
        signing_alg_values_supported (list): List of supported signing algorithm values.

    Returns:
        dict: Client attestation as decoded JWT payload.

    Raises:
        InvalidRequestException: If validation fails.

    References:
        - IT-WALLET v1.3.3 IT specifications: https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/wallet-attestation-issuance.html#wallet-app-and-wallet-unit-attestation-issuance
        - OAuth 2.0 Attestation-Based Client Authentication: https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/07/
    """
    if not client_attestation:
        logger.error(f"Invalid OAuth-Client-Attestation")
        raise InvalidRequestException("JWS validation failed: invalid OAuth-Client-Attestation")
    print("client_attestation: ", client_attestation)
    try: #decode and validate header & payload of attestation
        attestation_jwt_header = decode_jwt_header(client_attestation)
        attestation_jwt_payload = decode_jwt_payload(client_attestation)
        WalletInstanceAttestationHeader.model_validate(attestation_jwt_header)
        WalletInstanceAttestationPayload.model_validate(attestation_jwt_payload)
    except Exception as exc:
        logger.error("Invalid OAuth-Client-Attestation: %s", exc)
        raise InvalidRequestException("JWT validation failed: OAuth-Client-Attestation-PoP invalid structure") from exc

    if not (iss_ec_jwt := validate_subject_trust_chain(attestation_jwt_payload["iss"], authority_hints, httpc_params)):
        raise InvalidRequestException("Invalid Trust Chain: Cannot verify issuer for OAuth-Client-Attestation")

    wallet_provider_metadata = iss_ec_jwt.get("metadata", {}).get(METADATA_TYPE_WALLET_PROVIDER, {})
    sign_core_jwks = wallet_provider_metadata.get("jwks", {}).get("keys", [])

    #validate OAuth-Client-Attestation
    if not validate_jws(client_attestation, sign_core_jwks, signing_alg_values_supported):
        raise InvalidRequestException("JWS OAuth-Client-Attestation validation failed")

    #reference IT-WALLET v1.3.3 IT specifications
    cnf_key = attestation_jwt_payload.get("cnf", {}).get("jwk", {})
    if attestation_jwt_payload.get("sub") != key_from_jwk_dict(cnf_key).thumbprint("SHA-256").decode():
        raise InvalidRequestException("JWS OAuth-Client-Attestation validation failed: invalid sub")

    return attestation_jwt_payload
