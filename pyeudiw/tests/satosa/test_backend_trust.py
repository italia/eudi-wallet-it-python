import pytest

from unittest.mock import Mock, patch

from pyeudiw.satosa.backend import OpenID4VPBackend

from pyeudiw.tests.settings import (
    BASE_URL,
    CONFIG_DIRECT_TRUST,
    INTERNAL_ATTRIBUTES,
)


class TestOpenID4VPBackend:

    @pytest.fixture(autouse=True)
    def setup_direct_trust(self):
        self.backend = OpenID4VPBackend(
            Mock(),
            INTERNAL_ATTRIBUTES,
            CONFIG_DIRECT_TRUST,
            BASE_URL,
            "name"
        )

    def test_response_endpoint(self):
        # TODO
        pass
