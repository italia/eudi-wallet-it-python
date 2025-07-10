import pytest
from pydantic import ValidationError

from pyeudiw.satosa.backends.openid4vp.schemas.wallet_metadata import WalletMetadata


def test_alg_values_supported_string_valid():
    metadata = WalletMetadata(
        vp_formats_supported={"jwt_vp_json": {"alg": ["RS256"]}},
        alg_values_supported="RS256"
    )
    assert metadata.alg_values_supported == ["RS256"]

def test_alg_values_supported_list_string_valid():
    metadata = WalletMetadata(
        vp_formats_supported={"jwt_vp_json": {"alg": ["RS256"]}},
        alg_values_supported=["RS256"]
    )
    assert metadata.alg_values_supported == ["RS256"]

def test_alg_values_supported_string_invalid():
    with pytest.raises(ValidationError) as err:
        WalletMetadata(
            vp_formats_supported={"jwt_vp_json": {"alg": ["RS256"]}},
            alg_values_supported="invalid_alg_values_supported"
        )
    assert "Invalid value for alg_values_supported" in str(err.value)

def test_alg_values_supported_list_string_invalid():
    metadata = WalletMetadata(
        vp_formats_supported={"jwt_vp_json": {"alg": ["RS256"]}},
        alg_values_supported=["invalid_alg_values_supported"]
    )
    assert metadata.alg_values_supported == []

