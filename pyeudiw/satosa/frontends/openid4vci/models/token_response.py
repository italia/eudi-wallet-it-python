from typing import List, Optional

from pydantic import BaseModel
from satosa.response import Created

from pyeudiw.satosa.frontends.openid4vci.models.auhtorization_detail import (
    AuthorizationDetail,
)
from pyeudiw.tools.content_type import APPLICATION_JSON

# OAuth token_type value for DPoP-bound access tokens (RFC 9449). The literal is
# a public token-type label, not a credential; nosec silences bandit's B105
# heuristic that flags any identifier containing "token".
TOKEN_TYPE = "DPoP"  # nosec B105


class TokenResponse(BaseModel):
    """
    Pydantic model representing the response returned from the token endpoint.
    """

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    authorization_details: Optional[List[AuthorizationDetail]] = None

    @staticmethod
    def to_created_response(
        access_token: str,
        refresh_token: str,
        expires_in: int,
        authorization_details: List[AuthorizationDetail],
    ) -> Created:
        """
        Converts the token response to a `Created` HTTP response object.

        Returns:
            Created: An HTTP 201 Created response containing the JSON-serialized token response.
        """

        data = TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=TOKEN_TYPE,
            expires_in=expires_in,
            authorization_details=(
                None
                if not authorization_details and len(authorization_details) == 0
                else authorization_details
            ),
        )
        return Created(
            message=data.model_dump_json(),
            content=APPLICATION_JSON,
        )
