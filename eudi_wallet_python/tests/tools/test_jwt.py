import pytest

from eudi_wallet_python.tools.jwk import JWK, KeyType
from eudi_wallet_python.tools.jwt import JWE, decrypt_jwe, unpad_jwt_element


@pytest.mark.parametrize("jwk", [
    # TODO: Fix this test case
    # JWK(keyType=KeyType.EC),
    JWK(keyType=KeyType.RSA)])
def test_jwe(jwk):
    payload = {"test": "test"}
    jwe = JWE(payload, jwk)
    assert jwe.jwe

    decrypted = decrypt_jwe(jwe.jwe, jwk.as_dict())
    assert decrypted == payload


@pytest.mark.parametrize("jwk, position", [(JWK(keyType=KeyType.RSA), 0), (JWK(keyType=KeyType.EC), 0)])
def test_unpad_jwt_element(jwk, position):
    result = unpad_jwt_element(JWE({"test": "test"}, jwk).jwe, position)
    assert result
    assert result["alg"] == "RSA-OAEP"
    assert result["enc"] == "A256CBC-HS512"
    assert result["kid"] == jwk.jwk["kid"]

