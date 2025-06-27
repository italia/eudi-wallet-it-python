from satosa.context import Context

from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import VCIBaseEndpoint, GET_ACCEPTED_METHODS
from pyeudiw.satosa.frontends.openid4vci.models.credential_offer_request import CredentialOfferRequest
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import CONFIG_CTX
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON
)


class CredentialOfferHandler(VCIBaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the Credential offer endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)

    def endpoint(self, context: Context):
        """
        Handle a GET request to the credential_offer endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        try:
            validate_request_method(context.request_method, GET_ACCEPTED_METHODS)
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            CredentialOfferRequest.model_validate(
                context.request.query, context = {
                    CONFIG_CTX: self.config_utils
                })
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke credential_offer endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke credential_offer endpoint", e)

    def _validate_configs(self):
        self._validate_required_configs([
            ("metadata.oauth_authorization_server", self.config_utils.get_oauth_authorization_server()),
            ("metadata.openid_credential_issuer.credential_configurations_supported",  self.config_utils.get_credential_configurations_supported())
        ])