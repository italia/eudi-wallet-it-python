from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.verifier import SDJWTVerifier

from sd_jwt.utils.demo_utils import get_jwk
from sd_jwt.utils.formatting import textwrap_json
from sd_jwt.utils.yaml_specification import load_yaml_specification

from .utils import iat_now
from ..jwk import JWK

def _adapt_keys(settings: dict, issuer_key: JWK, holder_key: JWK):
    keys = {
        "key_size": 256,
        "kty": "EC",
        "issuer_key": issuer_key.as_dict(),
        "holder_key": holder_key.as_dict()
    }
    
    return get_jwk(keys, settings["no_randomness"], None)


def issue_sd_jwt(claims: dict, settings: dict, issuer_key: JWK, holder_key: JWK) -> str:
    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": iat_now() + (settings["default_exp"] * 60)  # in seconds
    }

    claims.update(claims)
        
    specification = load_yaml_specification(settings["specification_file"])
    
    use_decoys = specification.get("add_decoy_claims", False)
    
    adapted_keys = _adapt_keys(settings, issuer_key, holder_key)
    
    SDJWTIssuer.unsafe_randomness = settings["no_randomness"]
    sdjwt_at_issuer = SDJWTIssuer(
        claims,
        adapted_keys["issuer_key"],
        adapted_keys["holder_key"] if specification.get("key_binding", False) else None,
        add_decoy_claims=use_decoys,
    )
    
    return {"jws": textwrap_json(sdjwt_at_issuer.serialized_sd_jwt), "issuance": sdjwt_at_issuer.sd_jwt_issuance}

def verify_sd_jwt(sd_jwt_presentation: str, settings: dict, issuer_key: JWK, holder_key: JWK):
    
    adapted_keys = _adapt_keys(settings, issuer_key, holder_key)
    
    def cb_get_issuer_key(issuer: str):
        if issuer == settings["issuer"]:
            return adapted_keys["issuer_public_key"]
        else:
            raise Exception(f"Unknown issuer: {issuer}")
        
    specification = load_yaml_specification(settings["specification_file"])
    use_decoys = specification.get("add_decoy_claims", False)
    serialization_format = specification.get("serialization_format", "compact")
    
    sdjwt_at_verifier = SDJWTVerifier(
        sd_jwt_presentation,
        cb_get_issuer_key,
        None,
        None,
        serialization_format=serialization_format,
    )
    
    return sdjwt_at_verifier.get_verified_payload()