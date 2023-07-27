import pytest

from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt import (issue_sd_jwt, verify_sd_jwt, _adapt_keys)

from sd_jwt.utils.yaml_specification import load_yaml_specification

from sd_jwt.holder import SDJWTHolder


def test_issue_sd_jwt():
    issuer_jwk = JWK()
    holder_jwk = JWK()
    
    user_claims_path = "./pyeudiw/tests/tools/specifications.yml"
    
    issue_sd_jwt(
        user_claims_path, 
        {"issuer": "http://test.com", "default_exp": 60, "specification_file": "./pyeudiw/tests/tools/specifications.yml", "no_randomness": True},
        issuer_jwk,
        holder_jwk
    )
    
def test_verify_sd_jwt():    
    issuer_jwk = JWK()
    holder_jwk = JWK()
        
    user_claims_path = "./pyeudiw/tests/tools/specifications.yml"
    
    issued_jwt = issue_sd_jwt(
        user_claims_path, 
        {"issuer": "http://test.com", "default_exp": 60, "specification_file": user_claims_path, "no_randomness": True},
        issuer_jwk,
        holder_jwk
    )
    
    testcase = load_yaml_specification(user_claims_path)
    
    adapted_keys = _adapt_keys(
        {"issuer": "http://test.com", "default_exp": 60, "specification_file": user_claims_path, "no_randomness": True}, 
        issuer_jwk, holder_jwk)
    
    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format="compact",
    )
    sdjwt_at_holder.create_presentation(
        testcase,
        None,
        None,
        adapted_keys["holder_key"] if testcase.get("key_binding", False) else None,
    )
        
    verified_payload = verify_sd_jwt(
        sdjwt_at_holder.sd_jwt_presentation, 
        {
            "issuer": "http://test.com", 
            "verifier": "http://test.com",
            "default_exp": 60, 
            "specification_file": user_claims_path, 
            "no_randomness": True,
            "key_binding_nonce": ""
        }, issuer_jwk, holder_jwk)