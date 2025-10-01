import pytest

from pyeudiw.satosa.exceptions import InvalidRequestException


def test_invalid_request_exception():
    with pytest.raises(InvalidRequestException) as exc_info:
        raise InvalidRequestException("Missing 'client_id' parameter")

    assert str(exc_info.value) == "Missing 'client_id' parameter"
    assert exc_info.value.message == "Missing 'client_id' parameter"
