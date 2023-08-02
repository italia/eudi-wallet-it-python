import re
from pydantic import BaseModel, ValidationError
from typing_extensions import Annotated
from pydantic.functional_validators import AfterValidator

JWT_REGEX = r"(^[\w-]*.[\w-]*.[\w-]*~([\w-]*.[\w-]*.[\w-]*){1})"


def checkJWT(jwt: str) -> str:
    res = re.match(JWT_REGEX, jwt)
    if not res:
        raise ValidationError(f"Vp_token is not a jwt {jwt}")

    return jwt


def checkJWTList(jwt_list: list[str]) -> list[str]:
    if len(jwt_list) == 0:
        raise ValidationError("vp_token is empty")

    for jwt in jwt_list:
        checkJWT(jwt)

    return jwt_list


class DescriptorSchema(BaseModel):
    id: str
    path: str
    format: str


class PresentationSubmissionSchema(BaseModel):
    definition_id: str
    id: str
    descriptor_map: list[DescriptorSchema]


class ResponseSchema(BaseModel):
    state: str
    vp_token: Annotated[str, AfterValidator(
        checkJWT)] | Annotated[list[str], AfterValidator(checkJWTList)]
    presentation_submission: PresentationSubmissionSchema
