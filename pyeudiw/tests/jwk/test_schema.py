from pyeudiw.jwk.schemas.public import ECJwkSchema, JwkSchema, RSAJwkSchema


def test_valid_rsa_jwk():
    jwk_d = {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    JwkSchema(**jwk_d)
    RSAJwkSchema(**jwk_d)


def test_valid_ec_jwk():
    jwk_d = {
        "kty": "EC",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "use": "enc",
        "kid": "1",
    }
    JwkSchema(**jwk_d)
    ECJwkSchema(**jwk_d)


def test_invalid_keys():
    # table with keys that should fail jwk parsing
    bad_keys_table: list[tuple[dict, str]] = [
        ({"aaaa": "1"}, "non-sense key"),
        (
            {
                "kty": "RSA",
                "e": "AQAB",
                "alg": "RS256",
                "kid": "2011-04-29",
            },
            "rsa key with missing attribute [n]",
        ),
        (
            {
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "alg": "RS256",
                "kid": "2011-04-29",
            },
            "rsa key with unexpected attribute [x]",
        ),
        (
            {
                "kty": "EC",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "use": "enc",
                "kid": "1",
            },
            "ec key with missing attribute [crv]",
        ),
        (
            {
                "kty": "EC",
                "crv": "P-256",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "use": "enc",
                "kid": "1",
            },
            "ec key with missing attribute [x]",
        ),
        (
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "e": "AQAB",
                "use": "enc",
                "kid": "1",
            },
            "ec key with unexpected attribute [e]",
        ),
    ]
    for i, (bad_key, reason) in enumerate(bad_keys_table):
        try:
            JwkSchema(**bad_key)
            assert False, f"failed case {i}: parsing should fail due to: {reason}"
        except ValueError:
            assert True
