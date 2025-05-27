from typing import List, Optional

from pydantic import BaseModel
from satosa.response import Response

from pyeudiw.openid4vci.utils.content_type import APPLICATION_JSON


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

class CredentialEndpointResponse(BaseModel):
    """
    Represents the payload of a Credential Request, supporting both immediate and deferred flows.

    Attributes:
        claim (Optional[str]): Optional claim associated with the credential.
        description (Optional[str]): Optional description of the credential.
        reference (Optional[str]): Optional reference string.
        credentials (Optional[List[CredentialItem]]): REQUIRED if neither lead_time nor
            transaction_id are present. MUST NOT be present if lead_time or transaction_id are given.
        lead_time (Optional[int]): REQUIRED if credentials is not present. Specifies the number
            of seconds the Wallet needs before requesting the credential.
        notification_id (Optional[str]): OPTIONAL. MUST NOT be present if `credentials` is not given.
            Used in Notification Requests to identify a credential.
        transaction_id (Optional[str]): REQUIRED if `credentials` is not present.
            MUST NOT be present if `credentials` is given. Used in deferred credential flows.
    """

    credentials: Optional[List[CredentialItem]] = None
    lead_time: Optional[int] = None
    notification_id: Optional[str] = None
    transaction_id: Optional[str] = None

    @staticmethod
    def to_response() -> Response:
        """
        Create a SATOSA Response with a JSON payload.

        A `CredentialEndpointResponse` instance is created  and wrapped in a SATOSA `Response` object with appropriate
        headers.

        Returns:
            Response: A SATOSA Response object with:
                - application/json content type
                - payload
        """
        data = CredentialEndpointResponse()
        response = Response(
            message=data.model_dump_json(),
            content=APPLICATION_JSON,
        )
        return response
