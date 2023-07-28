from io import StringIO
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.verifier import SDJWTVerifier

from sd_jwt.utils.demo_utils import get_jwk
from sd_jwt.utils.formatting import textwrap_json
from sd_jwt.utils.yaml_specification import _yaml_load_specification

from pyeudiw.tools.utils import iat_now, gen_exp_time
from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import unpad_jwt_payload


def _adapt_keys(settings: dict, issuer_key: JWK, holder_key: JWK, kty: str = "EC", key_size: int = 256):
    keys = {
        "key_size": key_size,
        "kty": kty,
        "issuer_key": issuer_key.as_dict(),
        "holder_key": holder_key.as_dict()
    }

    return get_jwk(keys, settings["no_randomness"], None)


def load_specification_from_yaml_string(yaml_specification: str):
    return _yaml_load_specification(StringIO(yaml_specification))


def issue_sd_jwt(specification: dict, settings: dict, issuer_key: JWK, holder_key: JWK) -> str:
    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": gen_exp_time(settings["default_exp"])  # in seconds
    }

    specification.update(claims)
    use_decoys = specification.get("add_decoy_claims", False)
    adapted_keys = _adapt_keys(settings, issuer_key, holder_key)

    SDJWTIssuer.unsafe_randomness = settings["no_randomness"]
    sdjwt_at_issuer = SDJWTIssuer(
        specification,
        adapted_keys["issuer_key"],
        adapted_keys["holder_key"],
        add_decoy_claims=use_decoys,
    )

    return {"jws": textwrap_json(sdjwt_at_issuer.serialized_sd_jwt), "issuance": sdjwt_at_issuer.sd_jwt_issuance}


def _cb_get_issuer_key(issuer: str, settings: dict, adapted_keys: dict):
    if issuer == settings["issuer"]:
        return adapted_keys["issuer_public_key"]
    else:
        raise Exception(f"Unknown issuer: {issuer}")


def verify_sd_jwt(sd_jwt_presentation: str, specification: dict, settings: dict, issuer_key: JWK, holder_key: JWK) -> dict:

    adapted_keys = _adapt_keys(settings, issuer_key, holder_key)

    specification.get("add_decoy_claims", False)
    serialization_format = specification.get("serialization_format", "compact")

    sdjwt_at_verifier = SDJWTVerifier(
        sd_jwt_presentation,
        (lambda x: _cb_get_issuer_key(x, settings, adapted_keys)),
        None,
        None,
        serialization_format=serialization_format,
    )

    key_binding = unpad_jwt_payload(
        sdjwt_at_verifier._unverified_input_key_binding_jwt)

    return sdjwt_at_verifier.get_verified_payload(), key_binding
