from io import StringIO
from typing import Dict

from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.utils.demo_utils import get_jwk
from sd_jwt.utils.formatting import textwrap_json
from sd_jwt.utils.yaml_specification import _yaml_load_specification
from sd_jwt.verifier import SDJWTVerifier

from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.tools.utils import gen_exp_time, iat_now

from jwcrypto.jws import JWS
from json import dumps, loads

class TrustChainSDJWTIssuer(SDJWTIssuer):
    def __init__(self, user_claims: Dict, issuer_key, holder_key=None, sign_alg=None, add_decoy_claims: bool = False, serialization_format: str = "compact", additional_headers: dict = {}):
        self.additional_headers = additional_headers
        super().__init__(user_claims, issuer_key, holder_key, sign_alg, add_decoy_claims, serialization_format)
        
    def _create_signed_jws(self):
        self.sd_jwt = JWS(payload=dumps(self.sd_jwt_payload))

        _protected_headers = {"alg": self._sign_alg}
        if self.SD_JWT_HEADER:
            _protected_headers["typ"] = self.SD_JWT_HEADER
            
        for k, v in self.additional_headers.items():
            _protected_headers[k] = v
            
        self.sd_jwt.add_signature(
            self._issuer_key,
            alg=self._sign_alg,
            protected=dumps(_protected_headers),
        )

        self.serialized_sd_jwt = self.sd_jwt.serialize(
            compact=(self._serialization_format == "compact")
        )

        if self._serialization_format == "json":
            jws_content = loads(self.serialized_sd_jwt)
            jws_content[self.JWS_KEY_DISCLOSURES] = [d.b64 for d in self.ii_disclosures]
            self.serialized_sd_jwt = dumps(jws_content)

def _adapt_keys(settings: dict, issuer_key: JWK, holder_key: JWK, kty: str = "EC", key_size: int = 256):
    keys = {
        "key_size": key_size,
        "kty": kty,
        "issuer_key": issuer_key.as_dict() if issuer_key else {},
        "holder_key": holder_key.as_dict() if holder_key else {}
    }

    return get_jwk(keys, settings["no_randomness"], None)


def load_specification_from_yaml_string(yaml_specification: str):
    return _yaml_load_specification(StringIO(yaml_specification))


def issue_sd_jwt(specification: dict, settings: dict, issuer_key: JWK, holder_key: JWK, trust_chain: list[str] | None = None) -> str:
    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": gen_exp_time(settings["default_exp"])  # in seconds
    }

    specification.update(claims)
    use_decoys = specification.get("add_decoy_claims", False)
    adapted_keys = _adapt_keys(settings, issuer_key, holder_key)
    
    additional_headers = {"trust_chain": trust_chain} if trust_chain else {}

    TrustChainSDJWTIssuer.unsafe_randomness = settings["no_randomness"]
    sdjwt_at_issuer = TrustChainSDJWTIssuer(
        user_claims=specification,
        issuer_key=adapted_keys["issuer_key"],
        holder_key=adapted_keys["holder_key"],
        add_decoy_claims=use_decoys,
        additional_headers=additional_headers
    )

    return {"jws": sdjwt_at_issuer.serialized_sd_jwt, "issuance": sdjwt_at_issuer.sd_jwt_issuance}


def _cb_get_issuer_key(issuer: str, settings: dict, adapted_keys: dict):
    if issuer == settings["issuer"]:
        return adapted_keys["issuer_public_key"]
    else:
        raise Exception(f"Unknown issuer: {issuer}")


def verify_sd_jwt(sd_jwt_presentation: str, specification: dict, settings: dict, issuer_key: JWK, holder_key: JWK) -> dict:
    settings.update({"issuer": unpad_jwt_payload(sd_jwt_presentation)["iss"]})
    adapted_keys = _adapt_keys(settings, issuer_key, holder_key)

    serialization_format = "compact"
    sdjwt_at_verifier = SDJWTVerifier(
        sd_jwt_presentation,
        (lambda x: _cb_get_issuer_key(x, settings, adapted_keys)),
        None,
        None,
        serialization_format=serialization_format,
    )

    return sdjwt_at_verifier.get_verified_payload()
