from pyeudiw.tests.jwt import VALID_TC_JWT, VALID_JWE
from pyeudiw.jwt.exceptions import JWTInvalidElementPosition, JWTDecodeError

from pyeudiw.jwt.utils import decode_jwt_element, decode_jwt_header, decode_jwt_payload, is_jwt_format, is_jwe_format

def test_decode_jwt_element():
    payload = decode_jwt_element(VALID_TC_JWT, 1)
    assert payload
    assert payload["sub"] == "1234567890"
    assert payload["name"] == "John Doe"
    assert payload["iat"] == 1516239022

    header = decode_jwt_element(VALID_TC_JWT, 0)
    assert header
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"

def test_decode_jwt_element_signature_failure():
    try:
        decode_jwt_element(VALID_TC_JWT, 2)
        assert False
    except JWTDecodeError:
        assert True

def test_decode_jwt_element_invalid():
    try:
        decode_jwt_element(VALID_TC_JWT, -1)
        assert False
    except JWTInvalidElementPosition:
        assert True

    try:
        decode_jwt_element(VALID_TC_JWT, 3)
        assert False
    except JWTInvalidElementPosition:
        assert True

def test_decode_jwt_header():
    header = decode_jwt_header(VALID_TC_JWT)
    assert header
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"

def test_decode_jwt_payload():
    payload = decode_jwt_payload(VALID_TC_JWT)
    assert payload
    assert payload["sub"] == "1234567890"
    assert payload["name"] == "John Doe"
    assert payload["iat"] == 1516239022

def test_is_jwt_format():
    assert is_jwt_format(VALID_TC_JWT)

def test_is_jwt_format_invalid():
    assert not is_jwt_format("eyJ")

def test_is_jwe_format():
    assert is_jwe_format(VALID_JWE)

def test_is_not_jwt_format_jwe():
    assert not is_jwe_format(VALID_TC_JWT)

