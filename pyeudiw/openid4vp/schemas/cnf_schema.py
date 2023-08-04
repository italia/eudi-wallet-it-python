from pydantic import BaseModel

from pyeudiw.jwk.schema import JwkSchema


class CNFSchema(BaseModel):
    jwk: JwkSchema
