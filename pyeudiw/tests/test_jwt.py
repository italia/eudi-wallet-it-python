import pytest

from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwk.ec import new_ec_key


from pyeudiw.jwt import (DEFAULT_ENC_ALG_MAP, DEFAULT_ENC_ENC_MAP, JWEHelper,
                         JWSHelper)

from pyeudiw.jwt.utils import decode_jwt_header, is_jwe_format

JWKs_EC = [
    (new_ec_key('P-256'), {"key": "value"}),
    (new_ec_key('P-256'), "simple string"),
    (new_ec_key('P-256'), None),
]

JWKs_RSA = [
    (new_rsa_key(), {"key": "value"}),
    (new_rsa_key(), "simple string"),
    (new_rsa_key(), None),
]

JWKs = JWKs_EC + JWKs_RSA


@pytest.mark.parametrize("jwk, payload", JWKs)
def test_decode_jwt_header(jwk, payload):
    jwe_helper = JWEHelper(jwk)
    jwe = jwe_helper.encrypt(payload)
    assert jwe
    header = decode_jwt_header(jwe)
    assert header
    assert header["alg"] == DEFAULT_ENC_ALG_MAP[jwk.kty]
    assert header["enc"] == DEFAULT_ENC_ENC_MAP[jwk.kty]
    assert header["kid"] == jwk.kid

@pytest.mark.parametrize("jwk, payload", JWKs)
def test_jwe_helper_encrypt(jwk, payload):
    helper = JWEHelper(jwk)
    jwe = helper.encrypt(payload)
    assert jwe
    assert is_jwe_format(jwe)


@pytest.mark.parametrize("jwk, payload", JWKs)
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


@pytest.mark.parametrize("jwk, payload", JWKs)
def test_jws_helper_sign(jwk, payload):
    helper = JWSHelper(jwk)
    jws = helper.sign(payload)
    assert jws


@pytest.mark.parametrize("jwk, payload", JWKs)
def test_jws_helper_verify(jwk, payload):
    helper = JWSHelper(jwk)
    jws = helper.sign(payload)
    assert jws
    verified = helper.verify(jws)
    if not payload:
        payload = ""
    assert verified == payload or verified == payload.encode()


@pytest.mark.parametrize("jwk, payload", JWKs)
def test_jws_helper_verify_fail(jwk, payload):
    helper = JWSHelper(jwk)
    jws = helper.sign(payload)
    assert jws
    jws = jws + "a"
    with pytest.raises(Exception):
        helper.verify(jws)
