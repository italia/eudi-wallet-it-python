import pytest

from pyeudiw.satosa.utils.respcode import (ResponseCodeSource, create_code,
                                           recover_state)


def test_valid_resp_code():
    state = "state"
    key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    code = create_code(state, key)
    assert recover_state(code, key) == state


def test_invalid_resp_code():
    key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    try:
        recover_state("this_is_an_invalid_response_code", key)
        assert False
    except Exception:
        assert True


def test_bad_key():
    key = ""
    try:
        create_code("state", key)
        assert False
    except ValueError:
        assert True


class TestResponseCodeHelper:

    @pytest.fixture(autouse=True)
    def setup(self):
        key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        self.respose_code_helper = ResponseCodeSource(key)

    def test_valid_code(self):
        state = "state"
        code = self.respose_code_helper.create_code(state)
        assert self.respose_code_helper.recover_state(code) == state

    def test_invalid_code(self):
        try:
            self.respose_code_helper.create_code(
                "this_is_an_invalid_response_code")
            assert False
        except Exception:
            assert True
