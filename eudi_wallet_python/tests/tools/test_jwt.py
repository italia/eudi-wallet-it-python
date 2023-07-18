import pytest

from eudi_wallet_python.tools.jwk import JWK, KeyType
from eudi_wallet_python.tools.jwt import JWE, decrypt_jwe, unpad_jwt_header


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


@pytest.mark.parametrize("jwk", [JWK(keyType=KeyType.RSA), JWK(keyType=KeyType.EC)])
def test_unpad_jwt_element(jwk):
    result = unpad_jwt_header(JWE({"test": "test"}, jwk).jwe)
    assert result
    assert result["alg"] == "RSA-OAEP"
    assert result["enc"] == "A256CBC-HS512"
    assert result["kid"] == jwk.jwk["kid"]

