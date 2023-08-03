from pydantic import BaseModel, HttpUrl


class FederationEntity(BaseModel):
    organization_name: str
    homepage_uri: HttpUrl
    policy_uri: HttpUrl
    logo_uri: HttpUrl
    contacts: list[str]
