from pydantic import BaseModel, Field, field_validator


class QRCode(BaseModel):

    size: int = Field(..., gt=0)  # size must be greater than 0
    color: str  # no validation for color, assuming it will always be a valid hex color
    # expiration_time must be greater than 0
    expiration_time: int = Field(..., gt=0)
    logo_path: str

    @field_validator("logo_path")
    def must_start_with_slash(cls, v):
        if v.startswith("/"):
            raise ValueError(f'{v} must start without "/"')
        return v
