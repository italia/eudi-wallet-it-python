import logging
from typing import List, Optional

from pydantic import model_validator

from pyeudiw.openid4vci.models.openid4vci_basemodel import (
    OpenId4VciBaseModel,
    ENDPOINT_CTX
)
from pyeudiw.tools.exceptions import InvalidRequestException

logger = logging.getLogger(__name__)
OPEN_ID_CREDENTIAL_TYPE = "openid_credential"

class AuthorizationDetail(OpenId4VciBaseModel):
    type: str = None
    credential_configuration_id: str = None
    credential_identifiers: Optional[List[str]] = None # for token response

    @model_validator(mode='after')
    def check_authorization_detail(self) -> "AuthorizationDetail":
        endpoint = self.get_ctx(ENDPOINT_CTX)
        self.validate_type(endpoint)
        self.validate_credential_configuration_id(endpoint)
        return self

    def validate_credential_configuration_id(self, endpoint: str):
        self.credential_configuration_id = self.strip(self.credential_configuration_id)
        self.check_missing_parameter(self.credential_configuration_id, "authorization_details.credential_configuration_id", endpoint)
        credential_configurations_supported = self.get_config_utils().get_credential_configurations_supported()
        if self.credential_configuration_id not in [ccs.id for ccs in credential_configurations_supported.values()]:
            logger.error(f"invalid credential_configuration_ids {self.credential_configuration_id} in request `{endpoint}` endpoint")
            raise InvalidRequestException("invalid `authorization_details.credential_configuration_id` parameter")

    def validate_type(self, endpoint: str):
        self.type = self.strip(self.type)
        self.check_missing_parameter(self.type, "authorization_details.type", endpoint)
        if self.type != OPEN_ID_CREDENTIAL_TYPE :
            logger.error(f"invalid authorization_details.type {self.type} in request `{endpoint}` endpoint")
            raise InvalidRequestException("invalid `authorization_details.type` parameter")