from typing import Callable, Union

import jwcrypto.jwk
from sd_jwt.verifier import SDJWTVerifier

import pyeudiw.jwk


class VpVerifier:
    """VpVerifier validates and verify vp tokens
    """

    def verify():
        raise NotImplementedError

    def parse_digital_credential() -> dict:
        raise NotImplementedError

    def check_revocation_status():
        raise NotImplementedError


"""_CB_KetStore_T is a map intended to be used as (issuer, jwt header) -> jwk | jwks, where
    - issuer is a jwt issuer ad obtained in the `iss` claim
    - jwt header is a complete decoded jwt-jws header, expressed as dictionary (usually kid an alg 
        are the used claims, but this is not guaranteed)
    - jwk | jwks is the key associated to that issuer, compatible to that header

    The typical use case of _CB_KetStore_T is to wrap a store to a invocable method or
    functional closure.
"""
_CB_KetStore_T = Callable[[str, dict], Union[jwcrypto.jwk.JWK, jwcrypto.jwk.JWKSet]]


def wrap_to_callable_keystore(fixed_jwk: jwcrypto.jwk.JWK) -> _CB_KetStore_T:
    """wrap a jwk to a trivial keystore where the input `fixed_jwk` is always returned
    """
    return lambda iss, header: fixed_jwk


def process_vp(vp: str, issuer_jwk: pyeudiw.jwk.JWK, aud: str, nonce: str) -> dict:
    """TODO: metood stub per raccogliere la logica di processing (verifica VC, verifica VP, extrazione credenziali disclosed)
    """
    _jwk = jwcrypto.jwk.JWK(**issuer_jwk.as_dict())
    # assume that it is a sd-jwt
    sdjwt_verifier = SDJWTVerifier(
        sd_jwt_presentation=vp,
        cb_get_issuer_key=wrap_to_callable_keystore(_jwk),
        expected_aud=aud,
        expected_nonce=nonce,
        serialization_format="compact"
    )
    # do it wallet specifics checks
    # todo ...
    result: dict = sdjwt_verifier.get_verified_payload()
    if "holder_disclosed_claims" in result.keys():
        result = result["holder_disclosed_claims"]  # TODO: what is this? verify
    if "verified_claims" in result:
        # TODO: flatten user attributes? what is this
        claims: dict = result["verified_claims"].get("claims", {})
        if not isinstance(claims, dict):
            raise Exception(f"vp payload of vc+sd-jwt result has unexpected formatting: {result}")
        result.update(claims)
    # todo: verifica che forma ha il dizionario spulciando il codice
    return result
