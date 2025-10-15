import pytest

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.status_list.exceptions import (
    PositionOutOfRangeError,
    InvalidTokenFormatError,
)
from pyeudiw.status_list.helper import StatusListTokenHelper
from pyeudiw.tests.settings import DEFAULT_X509_LEAF_JWK


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

import zlib

from pycose.headers import KID, Algorithm
from pycose.messages import Sign1Message

from pyeudiw.status_list import encode_cwt_status_list_token, decode_cwt_status_list_token

@pytest.fixture
def cwt_payload():
    return (
        {'ALG': 'ES256',
         'CURVE': 'P_256',
         'D': b'\x8bA\xd0\x8a\xa0\xcf]\xff\x8c\xa8.\xfb\xeb;[\x80\xe0\x88\xf7\xe7\x80F\x17\x14s:\x89\xfb\xbf\xe1\xb6\xd7',
         'KID': b'f10aca0992694b3581f6f699bfc8a2c6cc687725',
         'KTY': 'EC2'},
        1,
        b"\xff" * 10  # 10 bytes all 1
    )

def test_encode_cwt_status_list_token_unsigned_and_without_map(cwt_payload):
    payload_data = {"data": "test"}
    payload_parts = ({}, {}, payload_data)
    bits = cwt_payload[1]
    lst = cwt_payload[2]
    token_unsigned = encode_cwt_status_list_token(payload_parts, bits, lst)
    _cwt_token_payload(token_unsigned,
                       {"bits": bits, "lst": lst},
                       payload_data)

def test_encode_cwt_status_list_token_unsigned_and_with_map(cwt_payload):
    payload_data = {"data": "test"}
    payload_to_decode = {"ttl": 4000}
    payload_parts = ({}, {}, payload_data | payload_to_decode)
    bits = cwt_payload[1]
    lst = cwt_payload[2]
    token_unsigned = encode_cwt_status_list_token(payload_parts, bits, lst, {"ttl": 65534})
    _cwt_token_payload(token_unsigned,
                       {"bits": bits, "lst": lst},
                       payload_data | {65534: payload_to_decode["ttl"]})

def test_encode_cwt_status_list_token_signed_and_without_map(cwt_payload):
    payload_data = {"data": "test"}
    payload_parts = ({}, {}, payload_data)
    bits = cwt_payload[1]
    lst = cwt_payload[2]
    token_signed = encode_cwt_status_list_token(payload_parts, bits, lst, private_key=cwt_payload[0])
    _cwt_token_payload(token_signed,
                       {"bits": bits, "lst": lst},
                       payload_data, payload_parts)

def test_encode_cwt_status_list_token_signed_and_with_map(cwt_payload):
    payload_data = {"data": "test"}
    payload_to_decode = {"ttl": 4000}
    payload_parts = ({}, {}, payload_data | payload_to_decode)
    bits = cwt_payload[1]
    lst = cwt_payload[2]
    token_signed = encode_cwt_status_list_token(payload_parts, bits, lst, {"ttl": 65534}, cwt_payload[0])
    _cwt_token_payload(token_signed,
                       {"bits": bits, "lst": lst},
                       payload_data | {65534: payload_to_decode["ttl"]}, payload_parts)

def _cwt_token_payload(token, expected_status_list, payload_data: dict | None = None, payload_parts: tuple | None = None):
    assert isinstance(token, bytes)
    decoded_payload = decode_cwt_status_list_token(token)
    assert 65533 in decoded_payload[2] #check contains status_list
    assert zlib.decompress(decoded_payload[2][65533]["lst"]) == expected_status_list["lst"]
    assert decoded_payload[2][65533]["bits"] == expected_status_list["bits"]
    if payload_data:
        assert payload_data.items() <= decoded_payload[2].items()
    assert decoded_payload[1][16] == 'application/statuslist+cwt'
    if payload_parts:
        assert KID in payload_parts[0] or b"KID" in payload_parts[0]
        assert Algorithm in payload_parts[0]
        msg = Sign1Message.decode(bytes.fromhex(token.decode()))
        assert isinstance(msg, Sign1Message)
        assert msg.signature is not None
        assert len(msg.signature) > 0

