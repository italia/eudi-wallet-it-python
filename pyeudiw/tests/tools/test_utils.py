import datetime
import sys
import unittest.mock

import freezegun
import pytest
import requests

from pyeudiw.tools.utils import (
    _lru_cached_get_http_url,
    cacheable_get_http_url,
    exp_from_now,
    iat_now,
    make_timezone_aware,
    random_token,
)


def test_make_timezone_aware():
    now = datetime.datetime.now()
    assert now.tzinfo is None
    aware = make_timezone_aware(now)
    assert aware.tzinfo is not None
    assert aware.tzinfo == datetime.timezone.utc
    print(aware)
    with pytest.raises(ValueError):
        make_timezone_aware(aware)
    aware = make_timezone_aware(now, tz=datetime.datetime.now().astimezone().tzinfo)
    assert aware.tzinfo is not None


def frozen_time(fake_now, function, *args):
    with freezegun.freeze_time(fake_now):
        return function(*args)


@pytest.mark.parametrize(
    "fake_now, timestamp",
    [
        ("2020-12-31 12:00:00", 1609416000),
        ("2000-10-02 12:23:14", 970489394),
        ("1992-09-03 22:00:00", 715557600),
    ],
)
def test_iat_now(fake_now, timestamp):
    iat = frozen_time(fake_now=fake_now, function=iat_now)
    assert iat == timestamp


@pytest.mark.parametrize(
    "fake_now, delta_mins, timestamp",
    [
        ("2020-12-31 12:00:00", 0, 1609416000),
        ("2000-10-02 12:23:14", 1, 970489454),
        ("1992-09-03 22:00:00", 2, 715557720),
    ],
)
def test_exp_from_now(fake_now, delta_mins, timestamp):
    exp = frozen_time(fake_now, exp_from_now, delta_mins)
    assert exp == timestamp


@pytest.mark.parametrize(
    "n",
    [
        -1,
        0,
        1,
        2,
        3,
        10,
        999,
        10**1000,
        2.0,
        sys.maxsize,
        sys.maxsize - 1,
        # sys.maxsize // 2 -1,
        "1",
    ],
)
def test_random_token(n):
    if type(n) is not int:
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

    if n == 0:
        assert rand == ""
        return

    assert rand
    assert len(rand) == n * 2
    _hex = int(rand, 16)
    assert type(_hex) is int


def test_cacheable_get_http_url():
    # DEV NOTE: for some reson, this test fails in the github action but works ok locally. This needs further investigation.
    tries = 5
    ok_response = requests.Response()
    ok_response.status_code = 200
    ok_response.headers.update({"Content-Type": "text/plain"})
    ok_response._content = b"Hello automated test"
    mocked_endpoint = unittest.mock.patch(
        "pyeudiw.tools.utils.get_http_url", return_value=[ok_response]
    )

    cache_ttl: int = 60 * 60 * 24 * 365  # 1 year
    httpc_p = {
        "connection": {
            "ssl": False,
        },
        "session": {"timeout": 1},
    }

    # clear cache so that it is not polluted from prev tests
    _lru_cached_get_http_url.cache_clear()
    mocked_endpoint.start()
    for _ in range(tries):
        resp = cacheable_get_http_url(
            cache_ttl, "http://location.example", httpc_p, http_async=False
        )
        assert resp.status_code == 200
        assert resp._content == b"Hello automated test"
    mocked_endpoint.stop()

    cache_misses = _lru_cached_get_http_url.cache_info().misses
    exp_cache_misses = 1
    cache_hits = _lru_cached_get_http_url.cache_info().hits
    exp_cache_hits = tries - 1
    assert (
        cache_misses == exp_cache_misses
    ), f"cache missed more that {exp_cache_misses} time: {cache_misses}; {_lru_cached_get_http_url.cache_info()}"
    assert (
        cache_hits == exp_cache_hits
    ), f"cache hit less than {exp_cache_hits} times: {cache_hits}"
