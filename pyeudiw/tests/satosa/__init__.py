from pyeudiw.tests.federation.base import (
    trust_chain_issuer,
    leaf_wallet_jwk,
    leaf_cred_jwk_prot
)
from pyeudiw.jwk import JWK
from pyeudiw.tests.settings import (
    CONFIG,
    CREDENTIAL_ISSUER_ENTITY_ID,
    CREDENTIAL_ISSUER_CONF,
)
from pyeudiw.sd_jwt import (
    _adapt_keys,
    issue_sd_jwt,
    load_specification_from_yaml_string,
    import_ec
)
from sd_jwt.holder import SDJWTHolder
from satosa.context import Context
from pyeudiw.storage.db_engine import DBEngine

issuer_jwk = JWK(leaf_cred_jwk_prot.serialize(private=True))
holder_jwk = JWK(leaf_wallet_jwk.serialize(private=True))

settings = CREDENTIAL_ISSUER_CONF
settings['issuer'] = CREDENTIAL_ISSUER_ENTITY_ID
settings['default_exp'] = CONFIG['jwt']['default_exp']

sd_specification = load_specification_from_yaml_string(settings["sd_specification"])

issued_jwt = issue_sd_jwt(
    sd_specification,
    settings,
    issuer_jwk,
    holder_jwk,
    trust_chain=trust_chain_issuer,
    additional_headers={"typ": "vc+sd-jwt"}
)

_adapt_keys(issuer_jwk, holder_jwk)

sdjwt_at_holder = SDJWTHolder(
    issued_jwt["issuance"],
    serialization_format="compact",
)

ec_key = import_ec(holder_jwk.key.priv_key, kid=holder_jwk.kid) if sd_specification.get(
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
    context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

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