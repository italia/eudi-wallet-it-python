import logging
from typing import List
from urllib.parse import urlparse

from pydantic import BaseModel, model_validator

from pyeudiw.openid4vci.exceptions.bad_request_exception import InvalidRequestException

logger = logging.getLogger(__name__)

class AuthorizationCode(BaseModel):
    issuer_state: str
    authorization_server: str

    @model_validator(mode='after')
    def check_authorization_code(self) -> "AuthorizationCode":
        if not self.issuer_state or self.issuer_state.strip():
            logger.error("missing 'grants.issuer_state' in request `credential_offer` endpoint")
            raise InvalidRequestException("missing `grants.issuer_state` parameter")

        self.validate_authorization_server()
        return self

    def validate_authorization_server(self):
        if not self.authorization_server:
            logger.error("missing 'grants.authorization_server' in request `credential_offer` endpoint")
            raise InvalidRequestException("missing `grants.authorization_server` parameter")

        authorization_servers = (self.__pydantic_context__.get("config", {})
                                     .get("metadata", {}).get("openid_credential_issuer", {}).get("authorization_servers", []))
        if self.authorization_server not in authorization_servers:
                logger.error("missing 'grants.authorization_server' in request `credential_offer` endpoint")
                raise InvalidRequestException("missing `grants.authorization_server` parameter")



class CredentialOfferRequest(BaseModel):
    credential_issuer: str
    credential_configuration_ids: List[str]
    grants: AuthorizationCode

    @model_validator(mode='after')
    def check_credential_offer(self) -> "CredentialOfferRequest":
        self.validate_credential_issuer()
        self.validate_credential_configuration_ids()
        AuthorizationCode.model_validate(
            self.grants,
            context = {"config": self.config})
        return self

    def validate_credential_configuration_ids(self):
        credential_configurations_supported = (self.__pydantic_context__.get("config", {})
                                               .get("metadata", {}).get("openid_credential_issuer", {}).get("credential_configurations_supported", {}))
        for req_ids in self.credential_configuration_ids:
            if req_ids not in [ccs["id"] for ccs in credential_configurations_supported.values()]:
                logger.error(f"invalid credential_configuration_ids {self.credential_configuration_ids} in request `credential_offer` endpoint")
                raise InvalidRequestException("invalid `credential_configuration_ids` parameter")


    def validate_credential_issuer(self):
        if not self.credential_issuer or self.credential_issuer.strip():
            logger.error("missing 'credential_issuer' in request `credential_offer` endpoint")
            raise InvalidRequestException("missing `credential_issuer` parameter")

        try:
            parsed_redirect_uri = urlparse(self.credential_issuer.strip())
            if not parsed_redirect_uri.scheme or not (parsed_redirect_uri.netloc or parsed_redirect_uri.path):
                logger.error(f"invalid credential_issuer value '{self.credential_issuer}' in `credential_offer` endpoint")
                raise InvalidRequestException("invalid credential_issuer")
        except Exception as e:
            logger.error(f"invalid credential_issuer value '{self.credential_issuer}' in `credential_offer` endpoint: {e}")
            raise InvalidRequestException("invalid credential_issuer")

