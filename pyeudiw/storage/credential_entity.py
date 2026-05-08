import itertools
from pydantic import BaseModel, Field
from datetime import datetime, timezone

_incremental_counter = itertools.count(1)


class CredentialEntity(BaseModel):
    """
    Data model representing a user credential entity for credential issuance.
    """

    user_id: str  # as fk for user.document_id
    incremental_id: int = Field(default_factory=lambda: next(_incremental_counter))
    revoked: bool = False
    identifier: str
    document_id: str
    creation_date: float
    update_date: float = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).timestamp()
    )
    revocation_date: float = 0.0
    type: str
    credential_id: str
