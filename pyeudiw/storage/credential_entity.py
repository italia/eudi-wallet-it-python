import itertools

from pydantic import BaseModel, Field

_incremental_counter = itertools.count(1)


class CredentialEntity(BaseModel):
    """
    Data model representing a user credential entity for credential issuance.
    """
    user_id: str #as fk for user.document_id
    incremental_id: int = Field(default_factory=lambda: next(_incremental_counter))
    revoked: bool = False
    identifier: str
