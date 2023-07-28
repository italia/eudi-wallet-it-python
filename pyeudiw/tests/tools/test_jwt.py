import pytest

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWEHelper, JWSHelper, DEFAULT_JWE_ALG, DEFAULT_JWE_ENC
from pyeudiw.jwt.utils import unpad_jwt_header

JWKs_EC = [
    (JWK(key_type="EC"), {"key": "value"}),
    (JWK(key_type="EC"), "simple string"),
    (JWK(key_type="EC"), None),
]

JWKs_RSA = [
    (JWK(key_type="RSA"), {"key": "value"}),
    (JWK(key_type="RSA"), "simple string"),
    (JWK(key_type="RSA"), None),
]

JWKs = JWKs_EC + JWKs_RSA


@pytest.mark.parametrize("jwk, payload", JWKs_RSA)
def test_unpad_jwt_header(jwk, payload):
    jwe_helper = JWEHelper(jwk)
    jwe = jwe_helper.encrypt(payload)
    assert jwe
    header = unpad_jwt_header(jwe)
    assert header
    assert header["alg"] == DEFAULT_JWE_ALG
    assert header["enc"] == DEFAULT_JWE_ENC
    assert header["kid"] == jwk.jwk["kid"]


@pytest.mark.parametrize("key_type", ["RSA", "EC"])
def test_jwe_helper_init(key_type):
    jwk = JWK(key_type=key_type)
    helper = JWEHelper(jwk)
    assert helper.jwk == jwk


@pytest.mark.parametrize("jwk, payload", JWKs)
def test_jwe_helper_encrypt(jwk, payload):
    helper = JWEHelper(jwk)
    jwe = helper.encrypt(payload)
    assert jwe


@pytest.mark.parametrize("jwk, payload", JWKs_RSA)
def test_jwe_helper_decrypt(jwk, payload):
    helper = JWEHelper(jwk)
    jwe = helper.encrypt(payload)
    assert jwe
    decrypted = helper.decrypt(jwe)
    if not payload:
        payload = ""
    assert decrypted == payload or decrypted == payload.encode()


@pytest.mark.parametrize("jwk, payload", JWKs)
def test_jwe_helper_decrypt_fail(jwk, payload):
    helper = JWEHelper(jwk)
    jwe = helper.encrypt(payload)
    assert jwe
    jwe = jwe + "a"
    with pytest.raises(Exception):
        helper.decrypt(jwe)


@pytest.mark.parametrize("key_type", ["RSA", "EC"])
def test_jws_helper_init(key_type):
    jwk = JWK(key_type=key_type)
    helper = JWSHelper(jwk)
    assert helper.jwk == jwk


@pytest.mark.parametrize("jwk, payload", JWKs_RSA)
def test_jws_helper_sign(jwk, payload):
    helper = JWSHelper(jwk)
    jws = helper.sign(payload)
    assert jws


@pytest.mark.parametrize("jwk, payload", JWKs_RSA)
def test_jws_helper_verify(jwk, payload):
    helper = JWSHelper(jwk)
    jws = helper.sign(payload)
    assert jws
    verified = helper.verify(jws)
    if not payload:
        payload = ""
    assert verified == payload or verified == payload.encode()


@pytest.mark.parametrize("jwk, payload", JWKs_RSA)
def test_jws_helper_verify_fail(jwk, payload):
    helper = JWSHelper(jwk)
    jws = helper.sign(payload)
    assert jws
    jws = jws + "a"
    with pytest.raises(Exception):
        helper.verify(jws)
