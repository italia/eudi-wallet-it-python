from typing import Optional

from pydantic import BaseModel


class UserEntity(BaseModel):
    """
    Data model representing a user entity for credential issuance.

    This model contains the core identity attributes typically included in
    digital credentials, such as personal details and place of birth.

    Attributes:
        given_name (str): The user's given (first) name.
        family_name (str): The user's family (last) name.
        birth_date (str): The user's date of birth in ISO format (YYYY-MM-DD).
        personal_administrative_number (str): The user's unique personal identifier, such as a fiscal code.
        birth_country (str): The ISO country code of the user's place of birth (e.g., "IT").
        birth_locality (str): The locality (city, town) where the user was born.
        portrait (Optional[str]): An optional base64-encoded image of the user's portrait.
    """
    given_name: str
    family_name: str
    birth_date: str
    personal_administrative_number: str #fiscal code
    birth_country: str
    birth_locality: str
    portrait: Optional[str]
