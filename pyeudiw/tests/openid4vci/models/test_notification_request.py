import random
import string

import pytest

from pyeudiw.openid4vci.models.notification_request import (
    NotificationRequest,
    ACCEPTED_EVENT
)
from pyeudiw.tools.exceptions import InvalidRequestException


@pytest.mark.parametrize("event_description",[
        "Valid description!",
        "Some#text[with]allowed-characters.",
        "!#$%&'()*+,-./:;<=>?@[]^_`{|}~",
        "ASCII only text without issues",
    ]
)
def test_valid_event_descriptions(event_description):
    payload = {
        "notification_id":"notif123",
        "event":"credential_accepted",
        "event_description": event_description
    }
    model = NotificationRequest.model_validate(payload)
    assert model.event_description == event_description.strip()


@pytest.mark.parametrize("event_description", ["", "  ", None])
def test_empty_or_missing_event_descriptions(event_description):
    payload = {
        "notification_id":"notif123",
        "event":"credential_accepted"
    }
    if event_description is not None:
        payload["event_description"] = event_description

    model = NotificationRequest.model_validate(payload)
    assert model.event_description == (event_description.strip() if event_description is not None else None)

@pytest.mark.parametrize("event_description",[
        "Contiene emoji 🚫",
        'Invalid "quotes"',
        "Invalid \\ backslash",
        "Café et crème",
        "控制字符",
        "\x19Invalid control char",
])
def test_invalid_event_descriptions(event_description):
    payload = {
        "notification_id":"notif123",
        "event":"credential_accepted"
    }
    if event_description is not None:
        payload["event_description"] = event_description

    with pytest.raises(InvalidRequestException, match="invalid `event_description` parameter"):
        NotificationRequest.model_validate(payload)

@pytest.mark.parametrize("event", ["", "  ", None])
def test_empty_or_missing_event(event):
    payload = {
        "notification_id":"notif123",
    }
    if event is not None:
        payload["event"] = event

    with pytest.raises(InvalidRequestException, match="missing `event` parameter"):
        NotificationRequest.model_validate(payload)

@pytest.mark.parametrize("notification_id", ["", "  ", None])
def test_empty_or_missing_notification_id(notification_id):
    payload = {
        "event":"credential_accepted",
    }
    if notification_id is not None:
        payload["notification_id"] = notification_id

    with pytest.raises(InvalidRequestException, match="missing `notification_id` parameter"):
        NotificationRequest.model_validate(payload)

@pytest.mark.parametrize("event", ACCEPTED_EVENT)
def test_invalid_event_value(event):
    payload = {
        "notification_id":"notif123",
    }
    if event is not None:
        payload["event"] = event.join(random.choices(string.ascii_letters + string.digits, k=8))

    with pytest.raises(InvalidRequestException, match="invalid `event` parameter"):
        NotificationRequest.model_validate(payload)

def test_valid_complete_request():
    payload = {
        "notification_id":"notif123",
        "event":"credential_accepted",
        "event_description": "Valid description!"
    }
    model = NotificationRequest.model_validate(payload)
    assert model.notification_id == "notif123"
    assert model.event == "credential_accepted"
    assert model.event_description == "Valid description!"
