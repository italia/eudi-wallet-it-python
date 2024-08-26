import pytest
from pyeudiw.satosa.utils.respcode import ResponseCodeHelper, create_response_code, validate_resp_code


def test_valid_resp_code():
    state = "state"
    key = "abc123ab"
    code = create_response_code(state, key)
    assert validate_resp_code(code, state, key) is True


def test_invalid_resp_code():
    state = "state"
    key = "abc123ab"
    assert validate_resp_code("badcode", state, key) is False


class TestResponseCodeHelper:

    @pytest.fixture(autouse=True)
    def setup(self):
        key = "abc123ab"
        self.respose_code_helper = ResponseCodeHelper(key)

    def test_valid_code(self):
        state = "state"
        code = self.respose_code_helper.create_code(state)
        assert self.respose_code_helper.validate_code(code, state) is True

    def test_invalid_code(self):
        state = "state"
        assert self.respose_code_helper.validate_code("badcode", state) is False
