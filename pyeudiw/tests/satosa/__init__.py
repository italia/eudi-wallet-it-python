from io import StringIO

from cryptojwt.jwk.jwk import key_from_jwk_dict
from satosa.context import Context

from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt.holder import SDJWTHolder
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.utils.yaml_specification import _yaml_load_specification
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.federation.base import leaf_cred_jwk_prot, leaf_wallet_jwk
from pyeudiw.tests.settings import (CONFIG, CREDENTIAL_ISSUER_CONF,
                                    CREDENTIAL_ISSUER_ENTITY_ID)
from pyeudiw.tools.utils import exp_from_now, iat_now

issuer_jwk = leaf_cred_jwk_prot.serialize(private=True)
holder_jwk = leaf_wallet_jwk.serialize(private=True)

settings = CREDENTIAL_ISSUER_CONF
settings['issuer'] = CREDENTIAL_ISSUER_ENTITY_ID
settings['default_exp'] = CONFIG['jwt']['default_exp']

sd_specification = _yaml_load_specification(
    StringIO(settings["sd_specification"]))


user_claims = {
    "iss": settings["issuer"],
    "iat": iat_now(),
    "exp": exp_from_now(settings["default_exp"])  # in seconds
}

issued_jwt = SDJWTIssuer(
    user_claims,
    issuer_jwk,
    holder_jwk,
    add_decoy_claims=sd_specification.get("add_decoy_claims", True),
    serialization_format=sd_specification.get(
        "serialization_format", "compact"),
    extra_header_parameters={"typ": "vc+sd-jwt"},
)


sdjwt_at_holder = SDJWTHolder(
    issued_jwt.sd_jwt_issuance,
    serialization_format="compact",
)

ec_key = key_from_jwk_dict(holder_jwk) if sd_specification.get(
    "key_binding", False) else None


def _create_vp_token(nonce: str, aud: str, holder_jwk: JWK, sign_alg: str) -> str:
    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format="compact",
    )

    sdjwt_at_holder.create_presentation(
        {},
        nonce,
        aud,
        holder_jwk,
        sign_alg=sign_alg,
    )

    return sdjwt_at_holder.sd_jwt_presentation


def _generate_response(state: str, vp_token: str) -> dict:
    return {
        "state": state,
        "vp_token": vp_token,
        "presentation_submission": {
            "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
            "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
            "descriptor_map": [
                {
                    "id": "pid-sd-jwt:unique_id+given_name+family_name",
                    "path": "$.vp_token.verified_claims.claims._sd[0]",
                    "format": "vc+sd-jwt"
                }
            ]
        }
    }


def _generate_post_context(context: Context, request_uri: str, encrypted_response: str) -> Context:
    context.request_method = "POST"
    context.request_uri = request_uri
    context.request = {"response": encrypted_response}
    context.http_headers = {
        "HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

    return context


def _initialize_session(db_engine: DBEngine, state: str, session_id: str, nonce: str) -> None:
    db_engine.init_session(
        state=state,
        session_id=session_id
    )
    doc_id = db_engine.get_by_state(state)["document_id"]

    db_engine.update_request_object(
        document_id=doc_id,
        request_object={"nonce": nonce, "state": state})
