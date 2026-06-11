from satosa.context import Context
from satosa.response import Response

from pyeudiw.satosa.frontends.openid4vci.endpoints.base_credential_endpoint import (
    BaseCredentialEndpoint,
)
from pyeudiw.satosa.frontends.openid4vci.models.deferred_credential_endpoint_request import (
    DeferredCredentialEndpointRequest,
)
from pyeudiw.satosa.frontends.openid4vci.models.deferred_credential_endpoint_response import (
    CredentialItem,
    DeferredCredentialEndpointResponse,
)
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import (
    OpenId4VciBaseModel,
)
from pyeudiw.satosa.frontends.openid4vci.storage.entity import AuthorizationSession


class DeferredCredentialHandler(BaseCredentialEndpoint):
    """
    Handle a POST request to the deferred_credential endpoint.
    """

    def validate_request(
        self, context: Context, entity: AuthorizationSession
    ) -> OpenId4VciBaseModel:
        """
        Validate a POST request to the deferred credential endpoint.

        This method checks whether the body of the incoming HTTP request
        contains a valid JSON structure that conforms to the
        DeferredCredentialEndpointRequest model.

        Args:
            context (Context): The SATOSA context containing request data.
            entity (AuthorizationSession): The stored session/entity related to the request.

        Raises:
            pydantic.ValidationError: If the request body does not match the expected schema.
        """

        return DeferredCredentialEndpointRequest.model_validate(
            **context.request.body.decode("utf-8")
        )

    def to_response(
        self, context: Context, auth_session: AuthorizationSession, credential_id: str | None
    , **kwargs) -> Response:
        """
        Generate a response containing the issued credential.

        This method handles the issuance of the requested credential (e.g., SD-JWT)
        and formats it into a compliant response using the
        DeferredCredentialEndpointResponse helper.

        Args:
            context (Context): The SATOSA context.
            auth_session (AuthorizationSession): The entity containing stateful session data.

        Returns:
            Response: A SATOSA HTTP response with the issued credential.
        """

        return DeferredCredentialEndpointResponse.to_response(
            [
                CredentialItem(credential=cred)
                for cred in self.build_credential(auth_session, credential_id)
            ]
        )
