from hashlib import sha256, sha512

import pytest

from pyeudiw.openid4vci.models.token_request import (
    TokenRequest,
    CODE_CHALLENGE_CTX,
    CODE_CHALLENGE_METHOD_CTX,
    REDIRECT_URI_CTX
)
from pyeudiw.satosa.schemas.config import PyeudiwFrontendConfig
from pyeudiw.tools.exceptions import InvalidRequestException


def get_valid_context(code_verifier="testverifier", redirect_uri="https://client.example.org/cb", challenge_method="s256", scopes_supported = ["scope1", "scope2", "openid"]):
    match challenge_method:
        case "s256":
            code_challenge = sha256(code_verifier.encode('utf-8')).hexdigest()
        case "s512":
            code_challenge = sha512(code_verifier.encode('utf-8')).hexdigest()
        case _:
            raise NotImplementedError(f"{challenge_method} not supported in test context")

    return {
        CODE_CHALLENGE_CTX: code_challenge,
        CODE_CHALLENGE_METHOD_CTX: challenge_method,
        REDIRECT_URI_CTX: redirect_uri,
        "config": PyeudiwFrontendConfig(**{
            "jwt": {
                "default_exp":60,
                "default_sig_alg": "ES256"
            },
            "metadata": {
                "oauth_authorization_server": {
                    "response_types_supported": ["code"],
                    "response_modes_supported": [
                        "form_post.jwt",
                        "query"
                    ],
                    "code_challenge_methods_supported": ["S256"],
                    "scopes_supported": scopes_supported
                },
                "openid_credential_issuer" : {
                    "credential_configurations_supported": {
                        "PDA1Credential" :{
                            "id": "eudiw.pda1.se"
                        },
                        "EHICCredential":{
                            "id": "eudiw.ehic.se"
                        }
                    },
                    "authorization_servers": [],
                    "credential_issuer":"",
                }
            }
        })
    }

def test_token_request_valid_authorization_code_grant():
    payload = {
        "grant_type": "authorization_code",
        "code": "abc123",
        "redirect_uri": "https://client.example.org/cb",
        "code_verifier": "testverifier"
    }
    req = TokenRequest.model_validate(payload, context=get_valid_context())
    assert req.grant_type == "authorization_code"

def test_token_request_missing_code_for_authorization_code():
    payload = {
        "grant_type": "authorization_code",
        "redirect_uri": "https://client.example.org/cb",
        "code_verifier": "testverifier"
    }
    with pytest.raises(InvalidRequestException, match="missing `code`"):
        TokenRequest.model_validate(payload, context=get_valid_context())

def test_token_request_invalid_redirect_uri():
    payload = {
        "grant_type": "authorization_code",
        "code": "abc123",
        "redirect_uri": "https://malicious.example.com/cb",
        "code_verifier": "testverifier"
    }
    with pytest.raises(InvalidRequestException, match="Invalid `redirect_uri`"):
        TokenRequest.model_validate(payload, context=get_valid_context())

def test_token_request_invalid_code_verifier():
    payload = {
        "grant_type": "authorization_code",
        "code": "abc123",
        "redirect_uri": "https://client.example.org/cb",
        "code_verifier": "wrongverifier"
    }
    with pytest.raises(InvalidRequestException, match="Invalid `code_verifier`"):
        TokenRequest.model_validate(payload, context=get_valid_context())

def test_token_request_valid_refresh_token_grant():
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": "some-refresh-token",
        "scope": "scope1 openid"
    }
    req = TokenRequest.model_validate(payload, context= get_valid_context(
        scopes_supported = ["scope1", "scope2", "openid"]
    ))
    assert req.grant_type == "refresh_token"

def test_token_request_invalid_scope():
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": "some-refresh-token",
        "scope": "unknown_scope"
    }

    with pytest.raises(InvalidRequestException, match="invalid scope value 'unknown_scope'"):
        TokenRequest.model_validate(payload, context= get_valid_context(
            scopes_supported = ["scope1", "scope2"]
        ))
