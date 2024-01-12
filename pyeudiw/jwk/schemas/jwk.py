from typing import Literal, Annotated, Union, Optional, List

from pydantic import BaseModel, Field


class JwkBaseModel(BaseModel):
    use: Optional[Literal["sig", "enc"]] = None
    kid: Optional[str] = None


class RSAJwkSchema(JwkBaseModel):
    kty: Literal["RSA"]
    n: str
    e: str


class ECJwkSchema(JwkBaseModel):
    kty: Literal["EC"]
    crv: Literal["P-256", "P-384", "P-521"]
    x: str
    y: str


JwkSchema = Annotated[Union[ECJwkSchema, RSAJwkSchema],
                      Field(discriminator="kty")]


class JwksSchema(BaseModel):
    keys: List[JwkSchema]
