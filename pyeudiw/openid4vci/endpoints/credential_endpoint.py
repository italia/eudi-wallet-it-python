from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_credential_endpoint import BaseCredentialEndpoint
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
from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity


class CredentialHandler(BaseCredentialEndpoint):
    """
    Handle a POST request to the credential endpoint.
    Args:
        context (Context): The SATOSA context.
    Returns:
        A Response object.
    """

    def validate_request(self, context: Context, entity: OpenId4VCIEntity):
        """
        Validate a POST request to the credential endpoint.

        This method checks whether the body of the incoming HTTP request
        contains a valid JSON structure that conforms to the
        CredentialEndpointRequest model.

        Args:
            context (Context): The SATOSA context containing request data.
            entity (OpenId4VCIEntity): The stored session/entity related to the request.

        Raises:
            pydantic.ValidationError: If the request body does not match the expected schema.
        """
        c_req = CredentialEndpointRequest.model_validate(self._get_body(context), context = {
            AUTHORIZATION_DETAILS_CTX: entity.authorization_details
        })
        proof_jws_helper = JWSHelper(self.config["metadata_jwks"])
        ProofJWT.model_validate(
            proof_jws_helper.verify(c_req.proof.jwt), context = {
                CLIENT_ID_CTX: entity.client_id,
                ENTITY_ID_CTX: self.entity_id,
                NONCE_CTX: entity.c_nonce
            })

    def to_response(self, context: Context, entity: OpenId4VCIEntity) -> Response:
        """
        Generate a response containing the issued credential.

        This method handles the issuance of the requested credential (e.g., SD-JWT)
        and formats it into a compliant response using the
        CredentialEndpointResponse helper.

        Args:
            context (Context): The SATOSA context.
            entity (OpenId4VCIEntity): The entity containing stateful session data.

        Returns:
            Response: A SATOSA HTTP response with the issued credential.
        """
        cred = self.issue_sd_jwt(context)
        return CredentialEndpointResponse.to_response([
            CredentialItem(credential = cred["issuance"])
        ])
