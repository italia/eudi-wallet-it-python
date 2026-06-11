from typing import List, Optional

from satosa.response import Response

from pyeudiw.satosa.frontends.openid4vci.models.deferred_credential_endpoint_response import (
    CredentialItem,
    DeferredCredentialEndpointResponse,
)
from pyeudiw.tools.content_type import APPLICATION_JSON


class CredentialEndpointResponse(DeferredCredentialEndpointResponse):
    """
    Represents the payload of a Credential Request, supporting both immediate and deferred flows.
    """

    lead_time: Optional[int] = None
    transaction_id: Optional[str] = None

    @staticmethod
    def to_response(credentials: List[CredentialItem]) -> Response:
        """
        Create a SATOSA Response with a JSON payload.

        A `CredentialEndpointResponse` instance is created  and wrapped in a SATOSA `Response` object with appropriate
        headers.

        Returns:
            Response: A SATOSA Response object with:
                - application/json content type
                - payload
        """
        data = CredentialEndpointResponse(credentials=credentials)
        return Response(
            message=data.model_dump_json(),
            content=APPLICATION_JSON,
        )
