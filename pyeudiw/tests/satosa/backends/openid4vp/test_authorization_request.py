import pytest

from pyeudiw.duckle_ql.utils import DUCKLE_PRESENTATION, DUCKLE_QUERY_KEY
from pyeudiw.satosa.backends.openid4vp.authorization_request import (
    build_authorization_request_claims,
    build_authorization_request_url,
    response_encryption_key_params,
)


def test_response_encryption_key_params():
    assert response_encryption_key_params({}) == {
        "kty": "EC",
        "crv": "P-256",
        "use": "enc",
        "alg": "ECDH-ES",
    }
    configured = response_encryption_key_params(
        {
            "jwt": {
                "response_encryption_kty": "EC",
                "response_encryption_crv": "P-384",
                "response_encryption_use": "enc",
                "default_enc_alg": "ECDH-ES",
            }
        }
    )
    assert configured["crv"] == "P-384"
    assert configured["alg"] == "ECDH-ES"


def test_build_authoriation_request_url():
    url = build_authorization_request_url(
        "haip",
        {
            "client_id": "openid_federation:https://rp.example",
            "request_uri": "https://rp.example/request-uri",
            "state": "abc",
            "request_uri_method": "get",
        },
    )
    assert url.startswith("haip-vp://?")
    assert "client_id=openid_federation%3Ahttps%3A%2F%2Frp.example" in url
    assert "request_uri=https%3A%2F%2Frp.example%2Frequest-uri" in url
    assert "request_uri_method=get" in url

    url = build_authorization_request_url(
        "openid4vp",
        {
            "client_id": "x509_hash:abc",
            "request_uri": "https://rp.example/request-uri",
        },
    )
    assert url.startswith("openid4vp://?")


def test_build_authorization_request_claims():

    client_id = "openid_federation:http://rp.example/openid4vp"
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
        "openid_federation:custom-client-id", state, response_uri, config_custom_id
    )
    assert claims["iss"] == "OTHERRRRR"
    assert "client_id_scheme" not in claims

    with pytest.raises(ValueError):
        build_authorization_request_claims(
            "http://rp.example/openid4vp", state, response_uri, config
        )

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
    client_metadata = {
        "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES"}]},
        "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
    }
    claims = build_authorization_request_claims(
        client_id,
        state,
        response_uri,
        config_dcql,
        submission_data=submission_data,
        client_metadata=client_metadata,
    )
    assert claims[DUCKLE_QUERY_KEY] == dcql_query
    assert "scope" not in claims
    assert claims["client_metadata"] == client_metadata
    assert "client_id_scheme" not in claims
    assert claims["response_type"] == "vp_token"
    assert claims["client_id"] == client_id
