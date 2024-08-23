from pydantic import BaseModel


class ResponseConfig(BaseModel):
    code_hmac_key: str
