from pyeudiw.satosa.utils.respcode import create_response_code, validate_resp_code


def test_valid_resp_code():
    state = "state"
    key = "abc123ab"
    code = create_response_code(state, key)
    assert validate_resp_code(code, state, key) is True


def test_invalid_resp_code():
    state = "state"
    key = "abc123ab"
    assert validate_resp_code("badcode", state, key) is False
