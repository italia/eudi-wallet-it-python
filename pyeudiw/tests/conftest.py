# Root conftest: exposes pyeudiw.tests.settings as pytest fixtures to reduce
# repetition of "from pyeudiw.tests.settings import CONFIG" etc. across tests.
# Use e.g. def test_foo(config): or def test_bar(config, base_url): instead of
# importing the same symbols in every test file.

import pytest

from pyeudiw.tests import settings


@pytest.fixture
def config():
    """Full backend CONFIG (OpenID4VP)."""
    return settings.CONFIG


@pytest.fixture
def config_direct_trust():
    """CONFIG for direct-trust-only backend."""
    return settings.CONFIG_DIRECT_TRUST


@pytest.fixture
def base_url():
    return settings.BASE_URL


@pytest.fixture
def httpc_params():
    return settings.httpc_params


@pytest.fixture
def internal_attributes():
    return settings.INTERNAL_ATTRIBUTES


@pytest.fixture
def default_x509_leaf_jwk():
    return settings.DEFAULT_X509_LEAF_JWK


@pytest.fixture
def default_x509_leaf_private_key():
    return settings.DEFAULT_X509_LEAF_PRIVATE_KEY
