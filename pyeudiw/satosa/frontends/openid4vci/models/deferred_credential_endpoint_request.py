import logging

from pydantic import model_validator

from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import (
    OpenId4VciBaseModel,
)

logger = logging.getLogger(__name__)


class DeferredCredentialEndpointRequest(OpenId4VciBaseModel):
    """
    Model representing the payload of a Deferred Credential Request.

    This request is used by the Wallet Instance to request a Credential that could not
    be issued immediately during the initial issuance flow. It must include a transaction
    identifier previously provided by the Credential Issuer in a 202 Accepted response.
    """

    transaction_id: str = None

    @model_validator(mode="after")
    def check_deferred_credential_endpoint_request(
        self,
    ) -> "DeferredCredentialEndpointRequest":
        self.validate_transaction_id()
        return self

    def validate_transaction_id(self):
        pass
