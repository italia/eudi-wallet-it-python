from satosa.context import Context
from satosa.response import Response

from pyeudiw.openid4vci.endpoints.base_credential_endpoint import BaseCredentialEndpoint
from pyeudiw.openid4vci.models.deferred_credential_endpoint_request import DeferredCredentialEndpointRequest
from pyeudiw.openid4vci.models.deferred_credential_endpoint_response import DeferredCredentialEndpointResponse, \
    CredentialItem
from pyeudiw.openid4vci.storage.entity import OpenId4VCIEntity


class DeferredCredentialHandler(BaseCredentialEndpoint):
    """
    Handle a POST request to the deferred_credential endpoint.
    Args:
        context (Context): The SATOSA context.
    Returns:
        A Response object.
    """

    def validate_request(self, context: Context, entity: OpenId4VCIEntity):
        """
        Validate a POST request to the deferred credential endpoint.

        This method checks whether the body of the incoming HTTP request
        contains a valid JSON structure that conforms to the
        DeferredCredentialEndpointRequest model.

        Args:
            context (Context): The SATOSA context containing request data.
            entity (OpenId4VCIEntity): The stored session/entity related to the request.

        Raises:
            pydantic.ValidationError: If the request body does not match the expected schema.
        """
        DeferredCredentialEndpointRequest.model_validate(**context.request.body.decode("utf-8"))

    def to_response(self, context: Context, entity: OpenId4VCIEntity) -> Response:
        """
        Generate a response containing the issued credential.

        This method handles the issuance of the requested credential (e.g., SD-JWT)
        and formats it into a compliant response using the
        DeferredCredentialEndpointResponse helper.

        Args:
            context (Context): The SATOSA context.
            entity (OpenId4VCIEntity): The entity containing stateful session data.

        Returns:
            Response: A SATOSA HTTP response with the issued credential.
        """
        cred = self.issue_sd_jwt(context)
        return DeferredCredentialEndpointResponse.to_response([
            CredentialItem(**cred["issuance"])
        ])
