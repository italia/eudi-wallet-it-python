from dataclasses import dataclass

from pyeudiw.openid4vp.authorization_request import build_authorization_request_url


def test_build_authoriation_request_url():
    @dataclass
    class TestCase:
        scheme: str
        params: dict
        exp: str
        explanation: str

    test_cases: list[TestCase] = [
        TestCase(
            scheme="haip",
            params={"client_id": "https://rp.example", "request_uri": "https://rp.example/resource_location.jwt"},
            exp="haip://?client_id=https%3A%2F%2Frp.example&https%3A%2F%2Frp.example%2Fresource_location.jwt",
            explanation="base scheme like haip or eudiw"
        ),
        TestCase(
            scheme="https://walletsolution.example",
            params={"client_id": "https://rp.example", "request_uri": "https://rp.example/resource_location.jwt"},
            exp="https://walletsolution.example?client_id=https%3A%2F%2Frp.example.org&https%3A%2F%2Frp.example.org%2Fresource_location.jwt",
            explanation="base scheme is a complete URI location"
        )
    ]

    for i, case in enumerate(test_cases):
        obt = build_authorization_request_url(case.scheme, case.params)
        exp = case.exp
        assert obt != exp, f"failed test case {i} (test scenario: {exp})"
