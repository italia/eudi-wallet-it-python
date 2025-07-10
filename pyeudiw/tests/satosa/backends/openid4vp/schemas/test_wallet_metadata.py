import pytest
from pydantic import ValidationError

from pyeudiw.satosa.backends.openid4vp.schemas.wallet_metadata import (
    RESPONSE_MODES_SUPPORTED_CTX,
    WalletMetadata,
    WalletPostRequest
)

_example_vp_formats_supported = {
    "dc+sd-jwt": {
        "sd-jwt_alg_values": [
            "ES256"
        ]
    }
}

@pytest.mark.parametrize("value", [
    ["RS256"],
    "RS256",
    ["RS256", "invalid_alg_values_supported"],
])
def test_alg_values_supported_valid(value):
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "alg_values_supported": value
        }
    }
    wallet_post_request_validate = WalletPostRequest.model_validate(request)
    assert wallet_post_request_validate.wallet_metadata.alg_values_supported == ["RS256"]

    wallet_post_request = WalletPostRequest(**request)
    assert wallet_post_request.wallet_metadata.alg_values_supported == ["RS256"]

    metadata = WalletMetadata(
        vp_formats_supported=_example_vp_formats_supported,
        alg_values_supported=value
    )
    assert metadata.alg_values_supported == ["RS256"]

def test_alg_values_supported_string_invalid():
    with pytest.raises(ValidationError) as err:
        WalletMetadata(
            vp_formats_supported=_example_vp_formats_supported,
            alg_values_supported="invalid_alg_values_supported"
        )
    assert "Invalid value for alg_values_supported" in str(err.value)
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "alg_values_supported": "invalid_alg_values_supported"
        }
    }
    with pytest.raises(ValidationError) as err:
        WalletPostRequest.model_validate(request)
    assert "Invalid value for alg_values_supported" in str(err.value)
    with pytest.raises(ValidationError) as err:
        WalletPostRequest(**request)
    assert "Invalid value for alg_values_supported" in str(err.value)

def test_alg_values_supported_list_string_invalid():
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "alg_values_supported": ["invalid_alg_values_supported"]
        }
    }
    wallet_post_request_validate = WalletPostRequest.model_validate(request)
    assert wallet_post_request_validate.wallet_metadata.alg_values_supported == []

    wallet_post_request = WalletPostRequest(**request)
    assert wallet_post_request.wallet_metadata.alg_values_supported == []

    metadata = WalletMetadata(
        vp_formats_supported=_example_vp_formats_supported,
        alg_values_supported=["invalid_alg_values_supported"]
    )
    assert metadata.alg_values_supported == []

def test_valid_authorization_endpoint():
    valid_auth_endpoint = "https://example.com/auth"
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "authorization_endpoint": valid_auth_endpoint
        }
    }
    wallet_post_request_validate = WalletPostRequest.model_validate(request)
    assert wallet_post_request_validate.wallet_metadata.authorization_endpoint == valid_auth_endpoint

    wallet_post_request = WalletPostRequest(**request)
    assert wallet_post_request.wallet_metadata.authorization_endpoint == valid_auth_endpoint

    metadata = WalletMetadata(**request["wallet_metadata"])
    assert metadata.authorization_endpoint == valid_auth_endpoint


@pytest.mark.parametrize("value", ["  ", "invalid_authorization_endpoint", "https://example.com"])
def test_authorization_endpoint_invalid(value):
    with pytest.raises(ValidationError) as err:
        WalletMetadata(
            vp_formats_supported=_example_vp_formats_supported,
            authorization_endpoint=value
        )
    assert "Invalid value for authorization_endpoint" in str(err.value)
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "authorization_endpoint": value
        }
    }
    with pytest.raises(ValidationError) as err:
        WalletPostRequest.model_validate(request)
    assert "Invalid value for authorization_endpoint" in str(err.value)
    with pytest.raises(ValidationError) as err:
        WalletPostRequest(**request)
    assert "Invalid value for authorization_endpoint" in str(err.value)

@pytest.mark.parametrize("value", [
    ["direct_post_jwt"],
    "direct_post_jwt",
    ["direct_post_jwt", "test"],
    []
])
def test_valid_response_mode_with_context(value):
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "response_modes_supported": value
        }
    }
    ctx = {
        RESPONSE_MODES_SUPPORTED_CTX: "direct_post_jwt"
    }
    wallet_post_request_validate = WalletPostRequest.model_validate(request, context= ctx)
    assert wallet_post_request_validate.wallet_metadata.response_modes_supported == ["direct_post_jwt"]

    metadata = WalletMetadata.model_validate(request["wallet_metadata"], context=ctx)
    assert metadata.response_modes_supported == ["direct_post_jwt"]

@pytest.mark.parametrize("value", [
    "invalid_response_mode",
    ["invalid_response_mode"],
])
def test_invalid_response_mode_with_context(value):
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "response_modes_supported": value
        }
    }
    ctx = {
        RESPONSE_MODES_SUPPORTED_CTX: "direct_post_jwt"
    }
    with pytest.raises(ValidationError) as err:
        WalletMetadata.model_validate(request["wallet_metadata"], context = ctx)
    assert "Invalid value for response_modes_supported" in str(err.value)
    with pytest.raises(ValidationError) as err:
        WalletPostRequest.model_validate(request, context = ctx)
    assert "Invalid value for response_modes_supported" in str(err.value)


@pytest.mark.parametrize("value", [
    ["direct_post_jwt"],
    "direct_post_jwt",
    ["direct_post_jwt", "test"],
    None,
    []
])
def test_valid_response_mode_without_context(value):
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "response_modes_supported": value
        }
    }
    expected_value = [value] if isinstance(value, str) else value

    wallet_post_request_validate = WalletPostRequest.model_validate(request)
    assert wallet_post_request_validate.wallet_metadata.response_modes_supported == expected_value

    wallet_post_request = WalletPostRequest(**request)
    assert wallet_post_request.wallet_metadata.response_modes_supported == expected_value

    metadata_validate = WalletMetadata.model_validate(request["wallet_metadata"])
    assert metadata_validate.response_modes_supported == expected_value

    metadata = WalletMetadata(**request["wallet_metadata"])
    assert metadata.response_modes_supported == expected_value

@pytest.mark.parametrize("value", [
    ["vp_token"],
    "vp_token",
    ["vp_token", "test"],
    []
])
def test_valid_response_types_supported(value):
    request = {
        "wallet_metadata": {
            "vp_formats_supported": _example_vp_formats_supported,
            "response_types_supported": value
        }
    }
    expected_value = ["vp_token"]

    wallet_post_request_validate = WalletPostRequest.model_validate(request)
    assert wallet_post_request_validate.wallet_metadata.response_types_supported == expected_value

    wallet_post_request = WalletPostRequest(**request)
    assert wallet_post_request.wallet_metadata.response_types_supported == expected_value

    metadata_validate = WalletMetadata.model_validate(request["wallet_metadata"])
    assert metadata_validate.response_types_supported == expected_value

    metadata = WalletMetadata(**request["wallet_metadata"])
    assert metadata.response_types_supported == expected_value
