import re
from typing import Optional

from pydantic import model_validator

from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel

NOTIFICATION_ENDPOINT = "notification"

ACCEPTED_EVENT = [
    "credential_accepted",
    "credential_deleted",
    "credential_failure"
]
ALLOWED_EVENT_DESCRIPTION_REGEX = re.compile(r'^[\x20-\x21\x23-\x5B\x5D-\x7E]*$')


class NotificationRequest(OpenId4VciBaseModel):
    """
    Request body sent by the Wallet Instance to the Notification Endpoint
    to inform the Credential Issuer about events related to the issued Credential.
    """
    notification_id: str = None
    event: str = None
    event_description: Optional[str] = None

    @model_validator(mode='after')
    def check_notification_endpoint_request(self) -> "NotificationRequest":
        self.validate_notification_id()
        self.validate_event()
        self.validate_event_description()
        return self

    def validate_notification_id(self):
        self.notification_id = self.strip(self.notification_id)
        self.check_missing_parameter(self.notification_id, "notification_id", NOTIFICATION_ENDPOINT)
        #TODO: check MUST match the notification_id provided by the Credential Issuer.
        self.check_invalid_parameter(
            False,
            self.notification_id, "notification_id", NOTIFICATION_ENDPOINT
        )
    def validate_event(self):
        self.event = self.strip(self.event)
        self.check_missing_parameter(self.event, "event", NOTIFICATION_ENDPOINT)
        self.check_invalid_parameter(
            self.event not in ACCEPTED_EVENT,
            self.event, "event", NOTIFICATION_ENDPOINT
        )

    def validate_event_description(self):
        self.event_description = self.strip(self.event_description)
        if self.event_description:
            self.check_invalid_parameter(
                not ALLOWED_EVENT_DESCRIPTION_REGEX.match(self.event_description),
                self.event_description, "event_description", NOTIFICATION_ENDPOINT
            )


