from typing import Optional

from pydantic import BaseModel

class CredentialSpecificationConfig(BaseModel):
    """
        Configuration model for credential specification handling.
    """
    template: str
    expiry_days: Optional[int] = None