from pydantic import BaseModel

class CredentialConfigurationsConfig(BaseModel):
    """
        Configuration model for credential presentation handling.
    """
    lookup_source: str