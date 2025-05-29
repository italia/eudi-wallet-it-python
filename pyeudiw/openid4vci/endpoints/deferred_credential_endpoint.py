from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.models.deferred_credential_endpoint_request import DeferredCredentialEndpointRequest
from pyeudiw.openid4vci.models.deferred_credential_endpoint_response import DeferredCredentialEndpointResponse, \
    CredentialItem
from pyeudiw.openid4vci.utils.credentials.sd_jwt import SdJwt
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON
)
from pyeudiw.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.tools.validation import (
    validate_content_type,
    validate_request_method,
    validate_oauth_client_attestation
)


class DeferredCredentialHandler(BaseEndpoint):

    def __init__(self, config: dict, base_url: str, name: str):
        """
        Initialize the nonce endpoint class.
        Args:
            config (dict): The configuration dictionary.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, base_url, name)
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])

    def deferred_credential_endpoint(self, context: Context) -> Response:
        """
        Handle a POST request to the deferred_credential endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            validate_oauth_client_attestation(context)
            DeferredCredentialEndpointRequest.model_validate(**context.request.body.decode("utf-8"))
            cred = SdJwt(
                self.config,
                self.db_engine.get_by_session_id(self._get_session_id(context))
            )
            return DeferredCredentialEndpointResponse.to_response([
                CredentialItem(**cred.issue_sd_jwt()["issuance"])
            ])
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke deferred_credential endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke deferred_credential endpoint", e)