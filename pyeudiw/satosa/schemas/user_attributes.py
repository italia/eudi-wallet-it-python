from pydantic import BaseModel, field_validator


class UserAttributesConfig(BaseModel):
    unique_identifiers: list[str]
    subject_id_random_value: str

    @field_validator('subject_id_random_value')
    def validate_subject_id_random_value(cls, v):
        if v == 'CHANGEME!':
            raise ValueError('subject_id_random_value must not be "CHANGEME!"')
        return v
