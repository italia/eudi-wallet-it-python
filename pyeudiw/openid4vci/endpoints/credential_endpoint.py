from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.models.credential_endpoint_request import (
    CredentialEndpointRequest,
    ProofJWT
)
from pyeudiw.openid4vci.models.credential_endpoint_response import CredentialEndpointResponse
from pyeudiw.openid4vci.models.deferred_credential_endpoint_response import CredentialItem
from pyeudiw.openid4vci.models.openid4vci_basemodel import (
    AUTHORIZATION_DETAILS_CTX,
    CLIENT_ID_CTX,
    ENTITY_ID_CTX,
    NONCE_CTX
)
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


class CredentialHandler(BaseEndpoint):

    def __init__(self, config: dict, base_url: str, name: str):
        """
        Initialize the credential endpoint class.
        Args:
            config (dict): The configuration dictionary.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, base_url, name)
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])

    def credential_endpoint(self, context: Context) -> Response:
        """
        Handle a POST request to the credential endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            validate_oauth_client_attestation(context)
            entity = self.db_engine.get_by_session_id(self._get_session_id(context))
            c_req = CredentialEndpointRequest.model_validate(**context.request.body.decode("utf-8"), context = {
                AUTHORIZATION_DETAILS_CTX: entity.authorization_details
            })
            proof_jws_helper = JWSHelper(self.config["metadata_jwks"])
            ProofJWT.model_validate(
                **proof_jws_helper.verify(c_req.proof.jwt), context = {
                    CLIENT_ID_CTX: entity.client_id,
                    ENTITY_ID_CTX: self.entity_id,
                    NONCE_CTX: entity.c_nonce
                })
            cred = SdJwt(self.config, entity)
            return CredentialEndpointResponse.to_response([
                CredentialItem(**cred.issue_sd_jwt()["issuance"])
            ])
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke credential endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke credential endpoint", e)