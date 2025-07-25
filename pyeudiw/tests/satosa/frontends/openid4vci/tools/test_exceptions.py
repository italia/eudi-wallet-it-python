import pytest

from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)


def test_invalid_request_exception():
  with pytest.raises(InvalidRequestException) as exc_info:
    raise InvalidRequestException("Missing 'client_id' parameter")

  assert str(exc_info.value) == "Missing 'client_id' parameter"
  assert exc_info.value.message == "Missing 'client_id' parameter"


def test_invalid_scope_exception():
  with pytest.raises(InvalidScopeException) as exc_info:
    raise InvalidScopeException("Scope 'openid profile' not allowed")

  assert str(exc_info.value) == "Scope 'openid profile' not allowed"
  assert exc_info.value.message == "Scope 'openid profile' not allowed"
