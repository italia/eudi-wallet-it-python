import datetime
import time

import pytest

from pyeudiw.tools.date import is_valid_unix_timestamp


def test_valid_unix_timestamp_now():
    ts = int(time.time())
    assert is_valid_unix_timestamp(ts) is True

def test_invalid_unix_timestamp_one_year_ago():
    ts = int((datetime.datetime.now(datetime.timezone.utc).replace(year=datetime.datetime.now(datetime.timezone.utc).year - 1)).timestamp())
    assert is_valid_unix_timestamp(ts) is False

def test_valid_unix_timestamp_one_year_future():
    ts = int((datetime.datetime.now(datetime.timezone.utc).replace(year=datetime.datetime.now(datetime.timezone.utc).year + 1)).timestamp())
    assert is_valid_unix_timestamp(ts) is True

def test_too_old_unix_timestamp():
    ts = int((datetime.datetime.now(datetime.timezone.utc).replace(year=datetime.datetime.now(datetime.timezone.utc).year - 2)).timestamp())
    assert is_valid_unix_timestamp(ts) is False

def test_too_future_unix_timestamp():
    ts = int((datetime.datetime.now(datetime.timezone.utc).replace(year=datetime.datetime.now(datetime.timezone.utc).year + 2)).timestamp())
    assert is_valid_unix_timestamp(ts) is False

@pytest.mark.parametrize("value", [None, "", "1234567890", 0.0, 123.456, object()])
def test_invalid_types(value):
    assert is_valid_unix_timestamp(value) is False

def test_zero_timestamp():
    assert is_valid_unix_timestamp(0) is False

def test_negative_timestamp():
    assert is_valid_unix_timestamp(-1234567890) is False
