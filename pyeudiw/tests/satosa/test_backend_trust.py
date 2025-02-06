from unittest.mock import Mock

import pytest

from pyeudiw.satosa.backend import OpenID4VPBackend
from pyeudiw.tests.settings import BASE_URL, CONFIG, INTERNAL_ATTRIBUTES


class TestOpenID4VPBackend:

    @pytest.fixture(autouse=True)
    def setup_direct_trust(self):
        self.backend = OpenID4VPBackend(
            Mock(), INTERNAL_ATTRIBUTES, CONFIG, BASE_URL, "name"
        )

    def test_response_endpoint(self):
        # TODO
        pass
