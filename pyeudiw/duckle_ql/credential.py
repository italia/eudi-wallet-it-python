from typing import List

from pydantic import BaseModel


class Claim(BaseModel):
    """
    Represents a single claim with a JSON path.
    """
    path: List[str]


class Meta(BaseModel):
    """
    Metadata for a credential, including vct values.
    """
    vct_values: List[str]


class Credential(BaseModel):
    """
    Defines a single credential request.
    """
    id: str
    format: str
    meta: Meta
    claims: List[Claim]


class CredentialsRequest(BaseModel):
    """
    Root model containing a list of credential requests.
    """
    credentials: List[Credential]