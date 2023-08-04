from typing import Optional

from pydantic import BaseModel, create_model, HttpUrl
from pydantic_core.core_schema import FieldValidationInfo
from typing_extensions import Annotated, Literal
from pydantic.functional_validators import AfterValidator, field_validator

from pyeudiw.jwk.schema import JwkSchema
from pyeudiw.sd_jwt.schema import check_sd_jwt, check_sd_jwt_list


class DescriptorSchema(BaseModel):
    id: str
    path: str
    format: str


class PresentationSubmissionSchema(BaseModel):
    definition_id: str
    id: str
    descriptor_map: list[DescriptorSchema]


class ResponseSchema(BaseModel):
    state: Optional[str]
    vp_token: Annotated[str, AfterValidator(
        check_sd_jwt)] | Annotated[list[str], AfterValidator(check_sd_jwt_list)]
    presentation_submission: PresentationSubmissionSchema
