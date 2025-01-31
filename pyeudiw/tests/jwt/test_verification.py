from cryptojwt.jwk.ec import new_ec_key

from pyeudiw.jwt.helper import is_jwt_expired
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.verification import verify_jws_with_key
from pyeudiw.tools.utils import iat_now


def test_is_jwt_expired():
    jwk = new_ec_key('P-256')
    payload = {"exp": 1516239022}

    helper = JWSHelper(jwk)
    jws = helper.sign(payload)

    assert is_jwt_expired(jws) == True


def test_is_jwt_not_expired():
    jwk = new_ec_key('P-256')
    payload = {"exp": 999999999999}

    helper = JWSHelper(jwk)
    jws = helper.sign(payload)

    assert is_jwt_expired(jws) == False


def test_verify_jws_with_key():
    jwk = new_ec_key('P-256')
    payload = {"exp": iat_now()+5000}

    helper = JWSHelper(jwk)
    jws = helper.sign(payload)

    assert verify_jws_with_key(jws, jwk) == None
