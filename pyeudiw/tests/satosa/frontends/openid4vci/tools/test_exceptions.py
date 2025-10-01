import pytest

from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidScopeException

def test_invalid_scope_exception():
  with pytest.raises(InvalidScopeException) as exc_info:
    raise InvalidScopeException("Scope 'openid profile' not allowed")

  assert str(exc_info.value) == "Scope 'openid profile' not allowed"
  assert exc_info.value.message == "Scope 'openid profile' not allowed"
