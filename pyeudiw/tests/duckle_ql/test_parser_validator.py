from unittest.mock import Mock

import pytest

from pyeudiw.duckle_ql.handler import DuckleHandler
from pyeudiw.duckle_ql.parser_validator import ParserValidator

_MOCK_DUCKLE_CONFIG = {
    "dcql_query": '{"credentials":[{"id":"personal id data","format":"dc+sd-jwt","meta":{"vct_values":["https://trust-registry.eid-wallet.example.it/credentials/v1.0/personidentificationdata"]},"claims":[{"path":["given_name"]},{"path":["family_name"]}]},{"id":"wallet attestation","format":"mso_mdoc","meta":{"vct_values":["https://itwallet.registry.example.it/WalletAttestation"]},"claims":[{"path":["wallet_link"]},{"path":["wallet_name"]}]}]}'
}


class DuckleHandlerMock(DuckleHandler):
    def __init__(self):
        self.parse = Mock(return_value={"mock": "data"})
        self.validate = Mock()


@pytest.fixture
def duckle_handler_instance():
    return {"duckle": DuckleHandlerMock()}


@pytest.mark.parametrize(
    "config, active",
    [
        (_MOCK_DUCKLE_CONFIG, True),
        ({}, False),
        ({"some_other_config": {}}, False),
    ],
)
def test_is_active_duckle_request(duckle_handler_instance, config, active):
    assert ParserValidator({"some": "token"}, duckle_handler_instance, config).is_active_duckle_request() is active


@pytest.mark.parametrize(
    "config",
    [
        _MOCK_DUCKLE_CONFIG,
        {},
        {"some_other_config": {}},
    ],
)
def test_is_active_duckle_request_always_false_when_token_is_a_list(duckle_handler_instance, config):
    assert ParserValidator([{"some": "token"}], duckle_handler_instance, config).is_active_duckle_request() is False
