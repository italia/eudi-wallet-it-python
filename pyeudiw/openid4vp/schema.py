from typing import Optional

from pydantic import BaseModel, create_model, HttpUrl
from pydantic_core.core_schema import FieldValidationInfo
from typing_extensions import Annotated, Literal
from pydantic.functional_validators import AfterValidator, field_validator

from pyeudiw.jwk.schema import JwkSchema
from pyeudiw.jwt.utils import is_jwt_format


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
    vp_token: str
    presentation_submission: PresentationSubmissionSchema

    @field_validator("vp_token")
    @classmethod
    def _check_vp_token(cls, vp_token):
        if is_jwt_format(vp_token):
            return vp_token
        else:
            raise ValueError("vp_token is not in a JWT format.")
