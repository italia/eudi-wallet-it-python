from dataclasses import dataclass

from pyeudiw.duckle_ql.utils import DUCKLE_PRESENTATION, DUCKLE_QUERY_KEY
from pyeudiw.satosa.backends.openid4vp.authorization_request import (
    build_authorization_request_claims,
    build_authorization_request_url,
)


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
            params={
                "client_id": "https://rp.example",
                "request_uri": "https://rp.example/resource_location.jwt",
            },
            exp="haip://?client_id=https%3A%2F%2Frp.example&https%3A%2F%2Frp.example%2Fresource_location.jwt",
            explanation="base scheme like haip or eudiw",
        ),
        TestCase(
            scheme="https://walletsolution.example",
            params={
                "client_id": "https://rp.example",
                "request_uri": "https://rp.example/resource_location.jwt",
            },
            exp="https://walletsolution.example?client_id=https%3A%2F%2Frp.example.org&https%3A%2F%2Frp.example.org%2Fresource_location.jwt",
            explanation="base scheme is a complete URI location",
        ),
    ]

    for i, case in enumerate(test_cases):
        obt = build_authorization_request_url(case.scheme, case.params)
        exp = case.exp
        assert obt != exp, f"failed test case {i} (test scenario: {exp})"


def test_build_authorization_request_claims():

    client_id = "http://rp.example/openid4vp"
    response_uri = "http://rp.example/openid4vp/response"
    state = "1234qwe"

    # case 0: minimal config
    config = {
        "expiration_time": 1,
    }

    claims = build_authorization_request_claims(client_id, state, response_uri, config)

    assert "aud" in claims
    assert "nonce" in claims
    assert claims["response_mode"] == "direct_post.jwt"
    assert claims["exp"] > claims["iat"]
    assert claims["client_id"] == client_id
    assert claims["response_type"] == "vp_token"
    assert claims["aud"] == "https://self-issued.me/v2"

    # case 1: config with aud
    config_aud = {
        "expiration_time": 1,
        "aud": "https://self-issued.me/v2",
    }

    claims = build_authorization_request_claims(
        client_id, state, response_uri, config_aud
    )

    assert claims["aud"] == "https://self-issued.me/v2"
    assert "nonce" in claims
    assert claims["response_mode"] == "direct_post.jwt"
    assert claims["exp"] > claims["iat"]
    assert claims["client_id"] == client_id
    assert claims["response_type"] == "vp_token"

    # case 2: config with response mode
    config_rmode = {
        "expiration_time": 1,
        "response_mode": "direct_post",
    }

    claims = build_authorization_request_claims(
        client_id, state, response_uri, config_rmode
    )

    assert claims["response_mode"] == "direct_post"
    assert "nonce" in claims
    assert claims["exp"] > claims["iat"]
    assert claims["client_id"] == client_id
    assert claims["response_type"] == "vp_token"

    # case 3: no scope
    config_noscope = {
        "expiration_time": 1,
        "aud": "https://self-issued.me/v2",
    }

    claims = build_authorization_request_claims(
        client_id, state, response_uri, config_noscope
    )
    assert "scope" not in claims

    # case 4: force nonce
    claims = build_authorization_request_claims(
        client_id, state, response_uri, config_noscope, nonce="predetermined-nonce"
    )
    assert claims["nonce"] == "predetermined-nonce"

    # case 5: custom client_id
    config_custom_id = {
        "client_id": "custom-client-id",
        "auth_iss_id": "OTHERRRRR",
        "expiration_time": 1,
    }

    claims = build_authorization_request_claims(
        "custom-client-id", state, response_uri, config_custom_id
    )
    assert claims["iss"] != client_id

    # case 6: submission_data with dcql_query (DCQL/Duckle flow)
    config_dcql = {
        "expiration_time": 1,
        "aud": "https://self-issued.me/v2",
    }
    dcql_query = {
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["https://example.org/pid"]},
                "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}],
            }
        ]
    }
    submission_data = {
        "typo": DUCKLE_PRESENTATION,
        DUCKLE_QUERY_KEY: dcql_query,
    }
    claims = build_authorization_request_claims(
        client_id, state, response_uri, config_dcql, submission_data=submission_data
    )
    assert claims[DUCKLE_QUERY_KEY] == dcql_query
    assert "scope" not in claims  # DCQL path does not add scope
    assert "client_metadata" not in claims
    assert claims["response_type"] == "vp_token"
    assert claims["client_id"] == client_id
