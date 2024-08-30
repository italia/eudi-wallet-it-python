from pydantic import BaseModel


class ResponseConfig(BaseModel):
    sym_key: str
