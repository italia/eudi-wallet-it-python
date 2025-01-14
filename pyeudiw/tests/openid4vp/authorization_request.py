from dataclasses import dataclass

from pyeudiw.openid4vp.authorization_request import build_authorization_request_claims, build_authorization_request_url


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


def test_build_authorization_request_claims():

    client_id = "http://rp.example/openid4vp"
    response_uri = "http://rp.example/openid4vp/response"
    state = "1234qwe"

    # case 0: minimal config
    config = {
        "scope": ["family_name", "given_name"],
        "expiration_time": 1,
        "presentation_definition": {
            "id": "global-id",
            "input_descriptors": [
                {
                    "id": "specific-id",
                    "purpose": "Request presentation holding Power of Representation attestation",
                    "format": {
                        "vc+sd-jwt": {}
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": [
                                    "$.vct"
                                ],
                                "filter": {
                                    "type": "string",
                                    "pattern": "urn:eu.europa.ec.eudi:por:1"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }

    claims = build_authorization_request_claims(client_id, state, response_uri, config)

    assert "aud" not in claims
    assert "nonce" in claims
    assert claims["response_mode"] == "direct_post.jwt"
    assert claims["scope"] in ("familiy_name given_name", "given_name family_name")
    assert claims["exp"] > claims["iat"]
    assert claims["client_id"] == client_id
    assert claims["response_type"] == "vp_token"

    # case 1: config with aud
    config_aud = {
        "scope": ["family_name", "given_name"],
        "expiration_time": 1,
        "aud": "https://self-issued.me/v2",
        "presentation_definition": {
            "id": "global-id",
            "input_descriptors": [
                {
                    "id": "specific-id",
                    "purpose": "Request presentation holding Power of Representation attestation",
                    "format": {
                        "vc+sd-jwt": {}
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": [
                                    "$.vct"
                                ],
                                "filter": {
                                    "type": "string",
                                    "pattern": "urn:eu.europa.ec.eudi:por:1"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }

    claims = build_authorization_request_claims(client_id, state, response_uri, config_aud)

    assert claims["aud"] == "https://self-issued.me/v2"
    assert "nonce" in claims
    assert claims["response_mode"] == "direct_post.jwt"
    assert claims["scope"] in ("familiy_name given_name", "given_name family_name")
    assert claims["exp"] > claims["iat"]
    assert claims["client_id"] == client_id
    assert claims["response_type"] == "vp_token"

    # case 2: config with response mode
    config_rmode = {
        "scope": ["family_name", "given_name"],
        "expiration_time": 1,
        "response_mode": "direct_post",
        "presentation_definition": {
            "id": "global-id",
            "input_descriptors": [
                {
                    "id": "specific-id",
                    "purpose": "Request presentation holding Power of Representation attestation",
                    "format": {
                        "vc+sd-jwt": {}
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": [
                                    "$.vct"
                                ],
                                "filter": {
                                    "type": "string",
                                    "pattern": "urn:eu.europa.ec.eudi:por:1"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }

    claims = build_authorization_request_claims(client_id, state, response_uri, config_rmode)

    assert claims["response_mode"] == "direct_post"
    assert "nonce" in claims
    assert claims["response_mode"] == "direct_post.jwt"
    assert claims["scope"] in ("familiy_name given_name", "given_name family_name")
    assert claims["exp"] > claims["iat"]
    assert claims["client_id"] == client_id
    assert claims["response_type"] == "vp_token"
