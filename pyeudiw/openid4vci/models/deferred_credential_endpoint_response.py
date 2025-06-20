from typing import Optional, List

from pydantic import BaseModel
from satosa.response import Response

from pyeudiw.tools.content_type import APPLICATION_JSON


class CredentialItem(BaseModel):
    """
    Represents a single credential used in the credential request payload.

    Attributes:
        credential (str): REQUIRED. A string containing one issued PID/(Q)EAA.
            - If the requested format is 'dc+sd-jwt', this string MUST NOT be re-encoded.
            - If the requested format is 'mso_mdoc', it MUST be a base64url-encoded
              CBOR-encoded IssuerSigned structure (per ISO 18013-5).
    """
    credential: str

class DeferredCredentialEndpointResponse(BaseModel):
    """
    Represents a response returned for deferred credential issuance.

    Attributes:
        credentials (Optional[List[CredentialItem]]):
            A list of credentials that are ready to be retrieved. May be None if no credentials are available yet.

        notification_id (Optional[str]):
            An optional identifier for tracking the notification related to this deferred response.
    """
    credentials: Optional[List[CredentialItem]] = None
    notification_id: Optional[str] = None

    @staticmethod
    def to_response(credentials: List[CredentialItem]) -> Response:
        """
        Create a SATOSA Response with a JSON payload.

        A `DeferredCredentialEndpointResponse` instance is created  and wrapped in a SATOSA `Response` object with appropriate
        headers.

        Returns:
            Response: A SATOSA Response object with:
                - application/json content type
                - payload
        """
        data = DeferredCredentialEndpointResponse(credentials = credentials)
        response = Response(
            message=data.model_dump_json(),
            content=APPLICATION_JSON,
        )
        return response