
import datetime
import sys
import freezegun

import pytest

from pyeudiw.tools.utils import exp_from_now, iat_now, random_token, make_timezone_aware


def test_make_timezone_aware():
    now = datetime.datetime.now()
    assert now.tzinfo is None
    aware = make_timezone_aware(now)
    assert aware.tzinfo is not None
    assert aware.tzinfo == datetime.timezone.utc
    print(aware)
    with pytest.raises(ValueError):
        make_timezone_aware(aware)
    aware = make_timezone_aware(
        now, tz=datetime.datetime.now().astimezone().tzinfo)
    assert aware.tzinfo is not None


def frozen_time(fake_now, function, *args):
    with freezegun.freeze_time(fake_now):
        return function(*args)


@pytest.mark.parametrize("fake_now, timestamp", [
    ("2020-12-31 12:00:00", 1609416000),
    ("2000-10-02 12:23:14",  970489394),
    ("1992-09-03 22:00:00",  715557600),
])
def test_iat_now(fake_now, timestamp):
    iat = frozen_time(fake_now=fake_now, function=iat_now)
    assert iat == timestamp


@pytest.mark.parametrize("fake_now, delta_mins, timestamp", [
    ("2020-12-31 12:00:00", 0, 1609416000),
    ("2000-10-02 12:23:14",  1, 970489454),
    ("1992-09-03 22:00:00",  2, 715557720),
])
def test_exp_from_now(fake_now, delta_mins, timestamp):
    exp = frozen_time(fake_now, exp_from_now, delta_mins)
    assert exp == timestamp


def test_datetime_from_timestamp():
    # TODO: test the function after it is implemented
    pass


def test_get_http_url():
    # TODO: test the function after it is implemented
    pass


@pytest.mark.parametrize("n", [
    -1, 0, 1, 2, 3, 10, 999, 10**1000, 2.,
    sys.maxsize, sys.maxsize - 1,
    # sys.maxsize // 2 -1,
    "1"])
def test_random_token(n):
    if type(n) != int:
        with pytest.raises(TypeError):
            random_token(n)
        return

    if n < 0:
        with pytest.raises(ValueError):
            random_token(n)
        return

    if n >= sys.maxsize - 32:
        with pytest.raises(OverflowError):
            random_token(n)
        return

    rand = random_token(n)

    if (n == 0):
        assert rand == ''
        return

    assert rand
    assert len(rand) == n * 2
    hex = int(rand, 16)
    assert hex
    assert type(hex) == int
