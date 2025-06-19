from pydantic import BaseModel

class CredentialSpecificationConfig(BaseModel):
    """
        Configuration model for credential specification handling.
    """
    template: str