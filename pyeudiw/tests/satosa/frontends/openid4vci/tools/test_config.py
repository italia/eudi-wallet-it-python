import pytest

from pyeudiw.jwt.schemas.jwt import JWTConfig
from pyeudiw.satosa.frontends.openid4vci.tools.config import Openid4VciFrontendConfigUtils
from pyeudiw.satosa.schemas.credential_configurations import CredentialConfigurationsConfig
from pyeudiw.satosa.schemas.metadata import (
    OauthAuthorizationServerMetadata,
    OpenidCredentialIssuerMetadata,
    CredentialConfiguration
)
from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import MOCK_PYEUDIW_FRONTEND_CONFIG


@pytest.fixture
def mock_config_dict():
    return MOCK_PYEUDIW_FRONTEND_CONFIG


@pytest.fixture
def config_utils(mock_config_dict):
    return Openid4VciFrontendConfigUtils(mock_config_dict)


def test_get_jwt(config_utils):
    jwt = config_utils.get_jwt()
    assert isinstance(jwt, JWTConfig)
    assert jwt.default_sig_alg == "ES256"


def test_get_jwt_default_sig_alg(config_utils):
    assert config_utils.get_jwt_default_sig_alg() == "ES256"


def test_get_oauth_authorization_server(config_utils):
    auth_metadata = config_utils.get_oauth_authorization_server()
    assert isinstance(auth_metadata, OauthAuthorizationServerMetadata)
    assert auth_metadata.response_types_supported == ["code"]

def test_get_openid_credential_issuer(config_utils):
    issuer_metadata = config_utils.get_openid_credential_issuer()
    assert isinstance(issuer_metadata, OpenidCredentialIssuerMetadata)
    assert issuer_metadata.credential_configurations_supported == {
        "dc_sd_jwt_EuropeanDisabilityCard": {
            "format": "dc+sd-jwt",
            "scope": "EuropeanDisabilityCard"
        },
        "dc_sd_jwt_mDL": {
            "format": "dc+sd-jwt",
            "scope": "mDL",
            "cryptographic_binding_methods_supported": [
                "jwk"
            ]
        },
        'mso_mdoc_mDL': {
            'cryptographic_binding_methods_supported': ['cose_key'],
            'format': 'mso_mdoc',
            'scope': 'mDL',
            'doctype': 'org.iso.18013.5.1.mDL'
        }
    }


def test_get_credential_configurations_supported(config_utils):
    result = config_utils.get_credential_configurations_supported()
    assert isinstance(result, dict)
    assert set(result.keys()) == {'dc_sd_jwt_mDL', 'mso_mdoc_mDL', 'dc_sd_jwt_EuropeanDisabilityCard'}
    for k, v in result.items():
        assert isinstance(v, CredentialConfiguration)
        assert v.id == k
        assert v.scope is not None
        assert v.format is not None
        assert v.doctype == ("org.iso.18013.5.1.mDL" if v.id == 'mso_mdoc_mDL' else None)


def test_get_credential_configurations(config_utils):
    cred_conf = config_utils.get_credential_configurations()
    assert isinstance(cred_conf, CredentialConfigurationsConfig)
    assert cred_conf.lookup_source == "openid4vci"
