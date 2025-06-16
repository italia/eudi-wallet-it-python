import logging
from typing import List
from urllib.parse import urlparse

from pydantic import model_validator

from pyeudiw.openid4vci.models.openid4vci_basemodel import (
    OpenId4VciBaseModel,
    CONFIG_CTX
)
from pyeudiw.openid4vci.tools.exceptions import InvalidRequestException

logger = logging.getLogger(__name__)
CREDENTIAL_OFFER_ENDPOINT = "credential_offer"

class AuthorizationCode(OpenId4VciBaseModel):
    """
    Model representing the authorization code grants included in a Credential Offer request.

    Attributes:
        issuer_state (str): State identifier from the issuer, required for the credential offer.
        authorization_server (str): Identifier of the authorization server responsible for issuing the credential.

    Validation:
        - `issuer_state` must be a non-empty string.
        - `authorization_server` must be non-empty and must be listed in the allowed authorization servers
          as defined in the configuration context.

    Raises:
        InvalidRequestException: If any required field is missing or invalid.
    """

    issuer_state: str = None
    authorization_server: str = None

    @model_validator(mode='after')
    def check_authorization_code(self) -> "AuthorizationCode":
        """
        Validate the AuthorizationCode fields after model initialization.

        Strips whitespace and checks mandatory fields, raising exceptions on failure.

        Returns:
            AuthorizationCode: The validated AuthorizationCode instance.

        Raises:
            InvalidRequestException: On missing or invalid fields.
        """
        self.issuer_state = self.strip(self.issuer_state)
        self.check_missing_parameter(self.issuer_state, "grants.issuer_state", CREDENTIAL_OFFER_ENDPOINT)

        self.validate_authorization_server()
        return self

    def validate_authorization_server(self):
        """
        Validates the authorization server identifier against the configured list.

        Raises:
            InvalidRequestException: If the authorization server is missing or not allowed.
        """
        self.authorization_server = self.strip(self.authorization_server)
        self.check_missing_parameter(self.authorization_server, "grants.authorization_server", CREDENTIAL_OFFER_ENDPOINT)
        if self.authorization_server not in self.get_config_utils().get_openid_credential_issuer().authorization_servers:
            logger.error(f"invalid 'grants.authorization_server' {self.authorization_server} in request `credential_offer` endpoint")
            raise InvalidRequestException("invalid `grants.authorization_server` parameter")


class CredentialOfferRequest(OpenId4VciBaseModel):
    """
    Model representing a Credential Offer request payload.

    Attributes:
        credential_issuer (str): The URL identifying the credential issuer.
        credential_configuration_ids (List[str]): List of IDs of credential configurations requested.
        grants (AuthorizationCode): The grants object containing authorization details.

    Validation:
        - `credential_issuer` must be a valid, non-empty URI with scheme, netloc, and path.
        - `credential_configuration_ids` must be a non-empty list and each ID must be supported as per configuration.
        - `grants` must be provided and valid according to the AuthorizationCode model.

    Raises:
        InvalidRequestException: If any required field is missing or invalid.
    """

    credential_issuer: str = None
    credential_configuration_ids: List[str] = None
    grants: AuthorizationCode = None

    @model_validator(mode='after')
    def check_credential_offer(self) -> "CredentialOfferRequest":
        """
        Validates the CredentialOfferRequest after model initialization.

        Calls sub-validation methods for each field.

        Returns:
            CredentialOfferRequest: The validated CredentialOfferRequest instance.

        Raises:
            InvalidRequestException: On missing or invalid fields.
        """
        self.validate_credential_issuer()
        self.validate_credential_configuration_ids()
        self.validate_grants()
        return self

    def validate_grants(self):
        """
        Validates the grants field by delegating to AuthorizationCode validation.

        Raises:
            InvalidRequestException: If `grants` is missing or invalid.
        """
        self.check_missing_parameter(self.grants, "grants", CREDENTIAL_OFFER_ENDPOINT)
        AuthorizationCode.model_validate(
            self.grants,
            context={CONFIG_CTX: self.get_config()}
        )

    def validate_credential_configuration_ids(self):
        """
        Validates the credential configuration IDs.

        Ensures the list is non-empty and that each ID is supported by the issuer.

        Raises:
            InvalidRequestException: If the list is empty or contains unsupported IDs.
        """
        self.check_missing_parameter(self.credential_configuration_ids, "credential_configuration_ids", CREDENTIAL_OFFER_ENDPOINT)
        credential_configurations_supported = self.get_config_utils().get_credential_configurations_supported()
        supported_ids = [ccs.id for ccs in credential_configurations_supported.values()]
        for req_id in self.credential_configuration_ids:
            if req_id not in supported_ids:
                logger.error(f"invalid credential_configuration_ids {self.credential_configuration_ids} in request `credential_offer` endpoint")
                raise InvalidRequestException("invalid `credential_configuration_ids` parameter")

    def validate_credential_issuer(self):
        """
        Validates the credential issuer URI.

        Checks that the URI is non-empty and correctly structured with scheme, netloc, and path.

        Raises:
            InvalidRequestException: If the issuer URI is missing or invalid.
        """
        self.credential_issuer = self.strip(self.credential_issuer)
        self.check_missing_parameter(self.credential_issuer, "credential_issuer", CREDENTIAL_OFFER_ENDPOINT)
        try:
            parsed_redirect_uri = urlparse(self.credential_issuer)
            if not parsed_redirect_uri.scheme or not parsed_redirect_uri.netloc or not parsed_redirect_uri.path:
                logger.error(f"invalid credential_issuer value '{self.credential_issuer}' in `credential_offer` endpoint")
                raise InvalidRequestException("invalid `credential_issuer` parameter")
        except Exception as e:
            logger.error(f"invalid credential_issuer value '{self.credential_issuer}' in `credential_offer` endpoint: {e}")
            raise InvalidRequestException("invalid `credential_issuer` parameter")
