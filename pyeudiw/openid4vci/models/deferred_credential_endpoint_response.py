from typing import Optional

from pydantic import BaseModel, Field
from satosa.response import Response

from pyeudiw.openid4vci.utils.content_type import APPLICATION_JSON


class DeferredCredentialEndpointResponse(BaseModel):
    """
      Model representing the response to a Deferred Credential Request.

      The response may contain:
      - the Digital Credential(s), if available;
      - an optional `notification_id`;
      - or a 202 Accepted response with a `transaction_id` and `lead_time` if the credential is not yet ready.

      Attributes:
          transaction_id (Optional[str]): Returned when the Credential is not yet ready.
              It must match the value from the original request.
          lead_time (Optional[int]): The amount of time (in seconds) the Wallet must wait
              before retrying the Credential Request.
          credentials (Optional[list[str]]): Issued credentials. Only present when issuance
              is successful.
          notification_id (Optional[str]): Optional identifier of an issued credential, used for
              triggering client-side notifications.

      Example (pending):
          {
              "transaction_id": "8xLOxBtZp8",
              "lead_time": 864000
          }

      Example (success):
          {
              "credentials": ["<SD-JWT or MDOC content>"],
              "notification_id": "pid_123456"
          }

      References:
          - OpenID4VCI: Deferred Credential Response (Section 8.3)
      """

    transaction_id: Optional[str] = Field(
        default=None,
        description="Returned if credential is not ready yet; matches the original transaction_id."
    )
    lead_time: Optional[int] = Field(
        default=None,
        description="Time in seconds the Wallet must wait before retrying."
    )
    credentials: Optional[list[str]] = Field(
        default=None,
        description="List of issued credentials, if available."
    )
    notification_id: Optional[str] = Field(
        default=None,
        description="Identifier for issued credential, used in Wallet notifications."
    )

    @staticmethod
    def to_response() -> Response:
        """
        Create a SATOSA Response with a JSON payload.

        A `DeferredCredentialEndpointResponse` instance is created  and wrapped in a SATOSA `Response` object with appropriate
        headers.

        Returns:
            Response: A SATOSA Response object with:
                - application/json content type
                - payload
        """
        data = DeferredCredentialEndpointResponse()
        response = Response(
            message=data.model_dump_json(),
            content=APPLICATION_JSON,
        )
        return response
