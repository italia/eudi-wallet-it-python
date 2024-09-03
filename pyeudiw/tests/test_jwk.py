import pytest
from pydantic import TypeAdapter

from pyeudiw.jwk import JWK
from pyeudiw.jwk.schemas.public import ECJwkSchema, RSAJwkSchema, _JwkSchema_T


@pytest.mark.parametrize(
    "key, key_type, hash_func",
    [
        (None, None, None),
        (None, "EC", None),
        (None, "RSA", None)
    ]
)
def test_jwk(key, key_type, hash_func):
    jwk = JWK(key, key_type, hash_func if hash_func else 'SHA-256')
    assert jwk.key
    assert jwk.thumbprint
    assert jwk.jwk
    assert jwk.jwk["kid"] == jwk.thumbprint.decode()


def test_export_public__pem():
    jwk = JWK(key_type='RSA')
    assert jwk.public_key
    assert jwk.public_key["e"]
    assert jwk.public_key["n"]
    assert jwk.public_key["kid"] == jwk.jwk["kid"]
    assert jwk.public_key["kty"] == jwk.jwk["kty"]


def test_export_public__ec():
    jwk = JWK(key_type="EC")
    assert jwk.public_key
    assert jwk.public_key["crv"] == jwk.jwk["crv"]
    assert jwk.public_key["kty"] == jwk.jwk["kty"]
    assert jwk.public_key["kid"] == jwk.jwk["kid"]


@pytest.mark.parametrize("key_type", [None, "EC", "RSA"])
def test_export_private_pem(key_type):
    jwk = JWK(key_type=key_type)
    jwk_private_pem = jwk.export_private_pem()
    assert jwk_private_pem
    if key_type:
        assert f"BEGIN {key_type} PRIVATE KEY" in jwk_private_pem


def test_export_public_pem():
    jwk = JWK()
    jwk_public_pem = jwk.export_public_pem()
    assert jwk_public_pem
    assert "BEGIN PUBLIC KEY" in jwk_public_pem


@pytest.mark.parametrize("key_type", ["EC", "RSA"])
def test_dynamic_schema_validation(key_type):
    jwk = JWK(key_type=key_type)
    model = TypeAdapter(_JwkSchema_T).validate_python(jwk.as_dict())
    match key_type:
        case "EC":
            assert isinstance(model, ECJwkSchema)
            assert not isinstance(model, RSAJwkSchema)
        case "RSA":
            assert isinstance(model, RSAJwkSchema)
            assert not isinstance(model, ECJwkSchema)
