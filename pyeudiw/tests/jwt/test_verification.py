from pyeudiw.jwt.verification import is_jwt_expired, verify_jws_with_key
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper

def test_is_jwt_expired():
    jwk = JWK(key_type="EC") 
    payload = {"exp": 1516239022}

    helper = JWSHelper(jwk)
    jws = helper.sign(payload)

    assert is_jwt_expired(jws) == True

def test_is_jwt_not_expired():
    jwk = JWK(key_type="EC") 
    payload = {"exp": 999999999999}

    helper = JWSHelper(jwk)
    jws = helper.sign(payload)

    assert is_jwt_expired(jws) == False

def test_verify_jws_with_key():
    jwk = JWK(key_type="EC") 
    payload = {"exp": 1516239022}

    helper = JWSHelper(jwk)
    jws = helper.sign(payload)

    assert verify_jws_with_key(jws, jwk) == None

