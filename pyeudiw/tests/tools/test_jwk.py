import pytest

from pyeudiw.tools.jwk import JWK, KeyType


@pytest.mark.parametrize("key, key_type, hash_func",
                         [(None, None, None), (None, KeyType.EC, None), (None, KeyType.RSA, None)])
def test_jwk(key, key_type, hash_func):
    jwk = JWK(key, key_type, hash_func if hash_func else 'SHA-256')
    assert jwk.key
    assert jwk.thumbprint
    assert jwk.jwk
    assert jwk.jwk["kid"] == jwk.thumbprint.decode()


def test_export_public__pem():
    jwk = JWK()
    jwk_public = jwk.export_public()
    assert jwk_public
    assert jwk_public["e"]
    assert jwk_public["n"]
    assert jwk_public["kid"] == jwk.jwk["kid"]
    assert jwk_public["kty"] == jwk.jwk["kty"]


def test_export_public__ec():
    jwk = JWK(keyType=KeyType.EC)
    jwk_public = jwk.export_public()
    print(jwk_public)
    assert jwk_public
    assert jwk_public["crv"] == jwk.jwk["crv"]
    assert jwk_public["kty"] == jwk.jwk["kty"]
    assert jwk_public["kid"] == jwk.jwk["kid"]


@pytest.mark.parametrize("key_type", [None, KeyType.EC, KeyType.RSA])
def test_export_private_pem(key_type):
    jwk = JWK(keyType=key_type)
    jwk_private_pem = jwk.export_private_pem()
    assert jwk_private_pem
    if key_type:
        assert f"BEGIN {key_type.name} PRIVATE KEY" in jwk_private_pem
    else:
        assert f"BEGIN {KeyType.RSA.name} PRIVATE KEY" in jwk_private_pem


def test_export_public_pem():
    jwk = JWK()
    jwk_public_pem = jwk.export_public_pem()
    assert jwk_public_pem
    assert "BEGIN PUBLIC KEY" in jwk_public_pem
