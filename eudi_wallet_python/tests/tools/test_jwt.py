import pytest

from eudi_wallet_python.tools.jwk import JWK, KeyType
from eudi_wallet_python.tools.jwt import JWE, decrypt_jwe, unpad_jwt_header


@pytest.mark.parametrize("jwk, payload", [
    # TODO: Fix this test case
    # JWK(keyType=KeyType.EC, ),
    (JWK(keyType=KeyType.RSA), {"test": "test"}),
    (JWK(keyType=KeyType.RSA), "payload"),
])
def test_jwe(jwk, payload):
    jwe = JWE(payload, jwk)
    assert jwe.jwe

    decrypted = decrypt_jwe(jwe.jwe, jwk.as_dict())
    assert decrypted == payload or decrypted == payload.encode()


@pytest.mark.parametrize("jwk, payload", [
    (JWK(keyType=KeyType.RSA), {"test": "test"}),
    (JWK(keyType=KeyType.EC), {"test": "test"}),
    (JWK(keyType=KeyType.RSA), "msg"),
])
def test_unpad_jwt_element(jwk, payload):
    result = unpad_jwt_header(JWE(payload, jwk).jwe)
    assert result
    assert result["alg"] == "RSA-OAEP"
    assert result["enc"] == "A256CBC-HS512"
    assert result["kid"] == jwk.jwk["kid"]


def test_decrypt_fail():
    with pytest.raises(ValueError):
        unpad_jwt_header("test")
