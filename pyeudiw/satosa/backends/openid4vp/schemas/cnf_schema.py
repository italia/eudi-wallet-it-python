from pydantic import BaseModel

from pyeudiw.jwk.schemas.public import JwkSchema


class CNFSchema(BaseModel):
    jwk: JwkSchema
