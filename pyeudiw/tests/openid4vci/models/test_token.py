import time

from pyeudiw.openid4vci.models.token import AccessToken, RefreshToken

def get_access_token():
    now = int(time.time())
    exp = now + 3600
    return AccessToken(
        iss="my_iss",
        aud="my_iss",
        exp=exp,
        iat=now,
        client_id="client123",
        sub="client123"
    )

def test_refresh_token_defaults_nbf_to_exp():
    access_token = get_access_token()
    refresh_token = RefreshToken(**access_token.model_dump())
    assert refresh_token.iss == access_token.iss
    assert refresh_token.aud == access_token.aud
    assert refresh_token.exp == access_token.exp
    assert refresh_token.iat == access_token.iat
    assert refresh_token.client_id == access_token.client_id
    assert refresh_token.sub == access_token.sub
    assert refresh_token.nbf == access_token.exp
    assert access_token.jti is not None
    assert refresh_token.jti == access_token.jti

def test_refresh_token_with_given_nbf():
    access_token = get_access_token()
    nbf = int(time.time()) + 1800
    refresh_token = RefreshToken(**access_token.model_dump(), nbf = nbf)
    assert refresh_token.iss == access_token.iss
    assert refresh_token.aud == access_token.aud
    assert refresh_token.exp == access_token.exp
    assert refresh_token.iat == access_token.iat
    assert refresh_token.client_id == access_token.client_id
    assert refresh_token.sub == access_token.sub
    assert refresh_token.nbf == nbf
    assert access_token.jti is not None
    assert refresh_token.jti == access_token.jti
