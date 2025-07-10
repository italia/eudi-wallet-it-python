import pytest
from pydantic import ValidationError

from pyeudiw.satosa.backends.openid4vp.schemas.wallet_metadata import WalletMetadata

_example_vp_formats_supported = {
    "dc+sd-jwt": {
        "sd-jwt_alg_values": [
            "ES256"
        ]
    }
}

def test_alg_values_supported_string_valid():
    metadata = WalletMetadata(
        vp_formats_supported=_example_vp_formats_supported,
        alg_values_supported="RS256"
    )
    assert metadata.alg_values_supported == ["RS256"]

def test_alg_values_supported_list_string_valid():
    metadata = WalletMetadata(
        vp_formats_supported=_example_vp_formats_supported,
        alg_values_supported=["RS256"]
    )
    assert metadata.alg_values_supported == ["RS256"]

def test_alg_values_supported_string_invalid():
    with pytest.raises(ValidationError) as err:
        WalletMetadata(
            vp_formats_supported=_example_vp_formats_supported,
            alg_values_supported="invalid_alg_values_supported"
        )
    assert "Invalid value for alg_values_supported" in str(err.value)

def test_alg_values_supported_list_string_invalid():
    metadata = WalletMetadata(
        vp_formats_supported=_example_vp_formats_supported,
        alg_values_supported=["invalid_alg_values_supported"]
    )
    assert metadata.alg_values_supported == []

def test_valid_authorization_endpoint():
    metadata = WalletMetadata(
        vp_formats_supported=_example_vp_formats_supported,
        authorization_endpoint="https://example.com/auth"
    )
    assert metadata.authorization_endpoint == "https://example.com/auth"


@pytest.mark.parametrize("value", ["  ", "invalid_authorization_endpoint", "https://example.com"])
def test_authorization_endpoint_invalid(value):
    with pytest.raises(ValidationError) as err:
        WalletMetadata(
            vp_formats_supported=_example_vp_formats_supported,
            authorization_endpoint=value
        )
    assert "Invalid value for authorization_endpoint" in str(err.value)
