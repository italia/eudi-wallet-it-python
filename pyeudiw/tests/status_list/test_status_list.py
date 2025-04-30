from pyeudiw.status_list.helper import StatusListTokenHelper
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.tests.settings import DEFAULT_X509_LEAF_JWK
from pyeudiw.status_list.exceptions import (
    PositionOutOfRangeError,
    InvalidTokenFormatError,
)

def test_StatusListHelper_jwt_parsing():
    helper = StatusListTokenHelper.from_token(
        "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.eyJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQWhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3RhdHVzbGlzdHMvMSIsInR0bCI6NDMyMDB9.2RSRdUce0QmRvsbJkt0Hr0Ny5c9Tim2yj43wMFU76xjv9TClW5-B65b9pZSraeoPv6OxTULb4dHiWK0O8oLi6g"
    )

    assert helper.get_status(0) == 1
    assert helper.get_status(1) == 0
    assert helper.get_status(2) == 0
    assert helper.get_status(3) == 1

    assert helper.is_expired() is False
    assert helper.ttl == 43200
    assert helper.iat == 1686920170
    assert helper.sub == "https://example.com/statuslists/1"
    assert helper.iss == "https://example.com"

def test_StausListHelper_cwt_parsing():
    helper = StatusListTokenHelper.from_token(
        "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d584027d5535dfe0a33291cc9bfb41053ad2493c49d1ee4635e12548a79bac92916845fee76799c42762f928441c5c344e3612381e0cf88f2f160b3e1f97728ec8403"
    )
    
    assert helper.get_status(0) == 1
    assert helper.get_status(1) == 0
    assert helper.get_status(2) == 0
    assert helper.get_status(3) == 1

    assert helper.is_expired() is False
    assert helper.ttl == 43200
    assert helper.iat == 1686920170
    assert helper.sub == "https://example.com/statuslists/1"


def test_StatusListHelper_2bit():
    jwt = JWSHelper(DEFAULT_X509_LEAF_JWK).sign(
        plain_dict={
            "exp": 2291720170,
            "iat": 1686920170,
            "iss": "https://example.com",
            "status_list": {
                "bits": 2,
                "lst": "eNo76fITAAPfAgc"
            },
            "sub": "https://example.com/statuslists/1",
            "ttl": 43200
        },
        protected={
            "typ": "statuslist+jwt"
        }
    )

    helper = StatusListTokenHelper.from_token(jwt)

    assert helper.get_status(0) == 1
    assert helper.get_status(1) == 2
    assert helper.get_status(2) == 0
    assert helper.get_status(3) == 3

def test_StatusListHelper_invalid_position():
    helper = StatusListTokenHelper.from_token(
        "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.eyJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQWhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3RhdHVzbGlzdHMvMSIsInR0bCI6NDMyMDB9.2RSRdUce0QmRvsbJkt0Hr0Ny5c9Tim2yj43wMFU76xjv9TClW5-B65b9pZSraeoPv6OxTULb4dHiWK0O8oLi6g"
    )

    try:
        helper.get_status(400)
    except PositionOutOfRangeError:
        assert True
    except Exception:
        assert False

    try:
        helper.get_status(-1)
    except PositionOutOfRangeError:
        assert True
    except Exception:
        assert False


def test_StausListHelper_jwt_invalid_token():
    try:
        StatusListTokenHelper.from_token(
            "invalid"
        )
    except InvalidTokenFormatError:
        assert True
    except Exception:
        assert False