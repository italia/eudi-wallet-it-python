from typing import List, Optional

from pydantic import BaseModel, TypeAdapter, model_validator

MSO_MDOC_FORMAT = "mso_mdoc"
VC_SD_JWT_FORMAT = "vc+sd-jwt"
DC_SD_JWT_FORMAT = "dc+sd-jwt"
SD_JWT_FORMATS = [VC_SD_JWT_FORMAT, DC_SD_JWT_FORMAT]
JWT_VC_JSON_LD = "jwt_vc_json-ld"
JWT_VC_JSON = "jwt_vc_json"
JWT_VC_JSON_FORMATS = [JWT_VC_JSON_LD, JWT_VC_JSON]

TOKEN_FORMAT_FIELD = "credential_format" # nosec B105

class DcqlCredential(BaseModel):
    credential_format: str

class DcqlMdocCredential(DcqlCredential):
    doctype: str
    namespaces: dict

class DcqlQuery(BaseModel):
    id: str
    format: str
    meta: dict
    claims: list[dict]

    @classmethod
    def parse(cls, obj):
        parsed_obj = super().model_validate(obj)
        if parsed_obj.format == MSO_MDOC_FORMAT:
            mdoc_claim_adapter = TypeAdapter(List[DcqlMdocClaim])
            parsed_obj.claims = mdoc_claim_adapter.validate_python(parsed_obj.claims)
            mdoc_meta_adapter = TypeAdapter(DcqlMdocMeta)
            parsed_obj.meta = mdoc_meta_adapter.validate_python(parsed_obj.meta)
        return parsed_obj

    @model_validator(mode="before")
    def validate(cls, values):
        """
        Validates dcql query obj.

        Args:
            cls: The class type.
            values (dict): The values to be validated.

        Raises:
            ValueError: If no formats are defined in the configuration.
        """
        if not values.get("id"):
            raise ValueError("'id' must define in query.")
        if not values.get("format"):
            raise ValueError("'format' must define in query.")
        return values

class DcqlMdocClaim(BaseModel):
    id: str
    namespace: str
    claim_name: str
    values: Optional[List[str]] = None

class DcqlMdocMeta(BaseModel):
    doctype_value: str