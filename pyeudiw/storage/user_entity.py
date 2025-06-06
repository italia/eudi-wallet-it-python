from typing import Optional

from pydantic import BaseModel


class UserEntity(BaseModel):
    """
    Data model representing a user entity for credential issuance.

    This model contains the core identity attributes typically included in
    digital credentials, such as personal details and place of birth.

    Attributes:
        name (str): The user's given (first) name.
        surname (str): The user's family (last) name.
        dateOfBirth (str): The user's date of birth in ISO format (YYYY-MM-DD).
        fiscal_code (str): The user's unique personal identifier, such as a fiscal code.
        countyOfBirth (str): The ISO country code of the user's place of birth (e.g., "IT").
        placeOfBirth (str): The locality (city, town) where the user was born.
        portrait (Optional[str]): An optional base64-encoded image of the user's portrait.
    """
    name: str
    surname: str
    dateOfBirth: str
    fiscal_code: str
    countyOfBirth: str
    placeOfBirth: str
    portrait: Optional[str]
    mail: str
