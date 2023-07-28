import pytest

from pyeudiw.jwk import JWK


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
