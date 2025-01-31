from dataclasses import dataclass
from pyeudiw.jwk import JWK
from pyeudiw.jwk.jwks import find_jwk_by_kid, find_jwk_by_thumbprint


def test_find_jwk_by_kid():
    @dataclass
    class TestCase:
        jwks: list[dict]
        kid: str
        expected: dict | None
        explanation: str

    raw_key_1 = {"crv": "P-256", "d": "eTEvyBCxriRg6juv_H4bLRgRkdMaCF91k4bLEsdB2yI", "kid": "adeyyLKVrJyu3CLC9ewDHrobulXBZNOfPYM_4bERHqk",
                 "kty": "EC", "use": "sig", "x": "--7isDCDQZF7cZL-UrvRCLV5Rfo2Di1gaPX6_5uGalA", "y": "e2svMtnHH4s5dOPg8YhuHw2lEPlnVpkKJO7PGQeMTFw"}
    raw_key_2 = {"crv": "P-256", "d": "dMCVfcZLPDMInj10w_aQdp-m4jZgwdZjDPwe5nKp-Lw", "kid": "m_r7iPJLNZmQN5sEbILXr41xjSjSzfa3PgM5yURIh2Y",
                 "kty": "EC", "use": "sig", "x": "PA0jE_-Sxhdon9MGmjpMqlUykAbNIBcRgSvgL0eOoJQ", "y": "PG-xPWEvEQxljYkBON1vGw9RTtDiDkMsRE1AOSo4ark"}
    raw_key_no_kid = {"crv": "P-256", "d": "Sz4XNTXk0JaUs6hoyMMUxCSqe9Jx_ciXyVGQj7JSW50", "kty": "EC", "use": "sig",
                      "x": "qojguJYLuM7ZtGspBfZ2SSrGgTnCgCUzjwUkOyOjGMk", "y": "uRUCqLQjngS0iBZlhHLEGMqpUAe4AMpmMMr6BUkRD50"}

    test_cases: list[TestCase] = [
        TestCase(
            jwks=[],
            kid="NMrR5wD0p-VqbRbR9ej6M16v5Fs7hLXwonO9vhJYsn8",
            expected=None,
            explanation="no keys"
        ),
        TestCase(
            jwks=[raw_key_1],
            kid=raw_key_1["kid"],
            expected=raw_key_1,
            explanation="one matching key"
        ),
        TestCase(
            jwks=[raw_key_1, raw_key_2],
            kid=raw_key_2["kid"],
            expected=raw_key_2,
            explanation="one matching key ot ouf two"
        ),
        TestCase(
            jwks=[raw_key_2],
            kid="NMrR5wD0p-VqbRbR9ej6M16v5Fs7hLXwonO9vhJYsn8",
            expected=None,
            explanation="no matching key"
        ),
        TestCase(
            jwks=[raw_key_no_kid],
            kid="NMrR5wD0p-VqbRbR9ej6M16v5Fs7hLXwonO9vhJYsn8",
            expected=None,
            explanation="no matching on key without explicit kid (note: here kid=thumbprint)"
        )
    ]
    for i, case in enumerate(test_cases):
        obt = find_jwk_by_kid(case.jwks, case.kid)
        assert obt == case.expected, f"failed case {i}, testcase: {case.expected}"


def test_find_jwk_by_thumbprint():
    @dataclass
    class TestCase:
        jwks: list[dict]
        thumbrpint: bytes
        expected: dict | None
        explanation: str

    raw_key_1 = {"crv": "P-256", "d": "eTEvyBCxriRg6juv_H4bLRgRkdMaCF91k4bLEsdB2yI", "kid": "adeyyLKVrJyu3CLC9ewDHrobulXBZNOfPYM_4bERHqk",
                 "kty": "EC", "use": "sig", "x": "--7isDCDQZF7cZL-UrvRCLV5Rfo2Di1gaPX6_5uGalA", "y": "e2svMtnHH4s5dOPg8YhuHw2lEPlnVpkKJO7PGQeMTFw"}
    raw_key_2 = {"crv": "P-256", "d": "dMCVfcZLPDMInj10w_aQdp-m4jZgwdZjDPwe5nKp-Lw", "kid": "m_r7iPJLNZmQN5sEbILXr41xjSjSzfa3PgM5yURIh2Y",
                 "kty": "EC", "use": "sig", "x": "PA0jE_-Sxhdon9MGmjpMqlUykAbNIBcRgSvgL0eOoJQ", "y": "PG-xPWEvEQxljYkBON1vGw9RTtDiDkMsRE1AOSo4ark"}
    # expected values obtained using an online calculator
    raw_thumprint_1 = b"adeyyLKVrJyu3CLC9ewDHrobulXBZNOfPYM_4bERHqk"
    raw_thumprint_2 = b"m_r7iPJLNZmQN5sEbILXr41xjSjSzfa3PgM5yURIh2Y"

    auto_key_1_jwk = JWK()
    auto_key_2_jwk = JWK(key_type="RSA")
    auto_key_1 = auto_key_1_jwk.as_dict()
    auto_key_2 = auto_key_2_jwk.as_dict()
    auto_thumprint_1 = auto_key_1_jwk.thumbprint
    auto_thumprint_2 = auto_key_2_jwk.thumbprint

    test_cases: list[TestCase] = [
        TestCase(
            jwks=[
                raw_key_1
            ],
            thumbrpint=raw_thumprint_1,
            expected=raw_key_1,
            explanation="one matching key"
        ),
        TestCase(
            jwks=[
                raw_key_2,
                raw_key_1
            ],
            thumbrpint=raw_thumprint_1,
            expected=raw_key_1,
            explanation="one matching key out of two"
        ),
        TestCase(
            jwks=[],
            thumbrpint=raw_thumprint_1,
            expected=None,
            explanation="no key"
        ),
        TestCase(
            jwks=[
                raw_key_1
            ],
            thumbrpint=raw_thumprint_2,
            expected=None,
            explanation="no matching key"
        ),
        TestCase(
            jwks=[auto_key_1],
            thumbrpint=auto_thumprint_1,
            expected=auto_key_1,
            explanation="one matching autorgenerated ECDAS key"
        ),
        TestCase(
            jwks=[auto_key_2],
            thumbrpint=auto_thumprint_2,
            expected=auto_key_2,
            explanation="one matching autorgenerated RSA key"
        ),
        TestCase(
            jwks=[raw_key_1, raw_key_2, auto_key_1, auto_key_2],
            thumbrpint=auto_thumprint_1,
            expected=auto_key_1,
            explanation="generic matching test"
        ),
        TestCase(
            jwks=[raw_key_2, auto_key_1, auto_key_2],
            thumbrpint=raw_thumprint_1,
            expected=None,
            explanation="generic non matching test"
        )
    ]
    for i, case in enumerate(test_cases):
        obt = find_jwk_by_thumbprint(case.jwks, case.thumbrpint)
        assert obt == case.expected, f"failed case {i}, testcase: {case.expected}"
