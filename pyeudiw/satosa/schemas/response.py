from pydantic import BaseModel


class ResponseConfig(BaseModel):
    hmac_key: str
