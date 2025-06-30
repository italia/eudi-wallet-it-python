from typing import Optional

from pydantic import BaseModel, Field


class StatusListConfig(BaseModel):
    """
        Configuration model for status_list handling.
    """
    path: Optional[str] = None
    exp: Optional[int] = Field(None, gt=0)  # status_list.exp must be greater than 0
    ttl: Optional[int] = Field(None, gt=0)  # status_list.ttl must be greater than 0

