import json

from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import JWS

import pyeudiw.federation.trust_chain_validator as tcv_test
from pyeudiw.tools.utils import exp_from_now, iat_now

httpc_params = {
    "connection": {"ssl": True},
    "session": {"timeout": 6},
}

NOW = iat_now()
EXP = exp_from_now(5000)

ec_crv = "P-256"
ec_alg = "ES256"

# Define intermediate ec
intermediate_jwk = new_ec_key(ec_crv, alg=ec_alg)

# Define TA ec
ta_jwk = new_ec_key(ec_crv, alg=ec_alg)

# Define leaf Credential Issuer
leaf_cred_jwk = new_ec_key(ec_crv, alg=ec_alg)
leaf_cred_jwk_prot = new_ec_key(ec_crv, alg=ec_alg)
leaf_cred = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://credential-issuer.example.org",
    "sub": "https://credential-issuer.example.org",
    "jwks": {"keys": []},
    "metadata": {
        "openid_credential_issuer": {"jwks": {"keys": []}},
        "federation_entity": {
            "organization_name": "OpenID Credential Issuer example",
            "homepage_uri": "https://credential-issuer.example.org/home",
            "policy_uri": "https://credential-issuer.example.org/policy",
            "logo_uri": "https://credential-issuer.example.org/static/logo.svg",
            "contacts": ["tech@credential-issuer.example.org"],
        },
    },
    "authority_hints": ["https://intermediate.eidas.example.org"],
}
leaf_cred["jwks"]["keys"] = [leaf_cred_jwk.serialize()]
leaf_cred["metadata"]["openid_credential_issuer"]["jwks"]["keys"] = [
    leaf_cred_jwk_prot.serialize()
]


# Define intermediate Entity Statement for credential
intermediate_es_cred = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://intermediate.eidas.example.org",
    "sub": "https://credential-issuer.example.org",
    "jwks": {"keys": []},
}
intermediate_es_cred["jwks"]["keys"] = [leaf_cred_jwk.serialize()]

# Define leaf Wallet Provider
leaf_wallet_jwk = new_ec_key(ec_crv, alg=ec_alg)
leaf_wallet = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://wallet-provider.example.org",
    "sub": "https://wallet-provider.example.org",
    "jwks": {"keys": []},
    "metadata": {
        "wallet_provider": {"jwks": {"keys": []}},
        "federation_entity": {
            "organization_name": "OpenID Wallet Verifier example",
            "homepage_uri": "https://wallet-provider.example.org/home",
            "policy_uri": "https://wallet-provider.example.org/policy",
            "logo_uri": "https://wallet-provider.example.org/static/logo.svg",
            "contacts": ["tech@wallet-provider.example.org"],
        },
    },
    "authority_hints": ["https://intermediate.eidas.example.org"],
}
leaf_wallet["jwks"]["keys"] = [leaf_wallet_jwk.serialize()]
leaf_wallet["metadata"]["wallet_provider"] = [leaf_wallet_jwk.serialize()]

# Define intermediate Entity Statement for wallet provider
intermediate_es_wallet = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://intermediate.eidas.example.org",
    "sub": "https://wallet-provider.example.org",
    "jwks": {"keys": [leaf_wallet_jwk.serialize()]},
}

# Intermediate EC
intermediate_ec = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://intermediate.eidas.example.org",
    "sub": "https://intermediate.eidas.example.org",
    "jwks": {"keys": [intermediate_jwk.serialize()]},
    "metadata": {
        "federation_entity": {
            "contacts": ["soggetto@intermediate.eidas.example.it"],
            "federation_fetch_endpoint": "https://intermediate.eidas.example.org/fetch",
            "federation_resolve_endpoint": "https://intermediate.eidas.example.org/resolve",
            "federation_list_endpoint": "https://intermediate.eidas.example.org/list",
            "homepage_uri": "https://soggetto.intermediate.eidas.example.it",
            "name": "Example Intermediate intermediate.eidas.example",
        }
    },
    "authority_hints": ["https://trust-anchor.example.org"],
}


# Define TA
ta_es = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://trust-anchor.example.org",
    "sub": "https://intermediate.eidas.example.org",
    "jwks": {"keys": [intermediate_jwk.serialize()]},
}

ta_ec = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://trust-anchor.example.org",
    "sub": "https://trust-anchor.example.org",
    "jwks": {"keys": [ta_jwk.serialize()]},
    "metadata": {
        "federation_entity": {
            "federation_fetch_endpoint": "https://trust-anchor.example.org/fetch",
            "federation_resolve_endpoint": "https://trust-anchor.example.org/resolve",
            "federation_list_endpoint": "https://trust-anchor.example.org/list",
            "organization_name": "TA example",
            "homepage_uri": "https://trust-anchor.example.org/home",
            "policy_uri": "https://trust-anchor.example.org/policy",
            "logo_uri": "https://trust-anchor.example.org/static/logo.svg",
            "contacts": ["tech@trust-anchor.example.org"],
        }
    },
    "constraints": {"max_path_length": 1},
}

# Sign step
leaf_cred_signer = JWS(leaf_cred, alg=ec_alg, typ="entity-statement+jwt")
leaf_cred_signed = leaf_cred_signer.sign_compact([leaf_cred_jwk])

leaf_wallet_signer = JWS(leaf_wallet, alg=ec_alg, typ="entity-statement+jwt")
leaf_wallet_signed = leaf_wallet_signer.sign_compact([leaf_wallet_jwk])


intermediate_signer_ec = JWS(intermediate_ec, alg=ec_alg, typ="entity-statement+jwt")
intermediate_ec_signed = intermediate_signer_ec.sign_compact([intermediate_jwk])


intermediate_signer_es_cred = JWS(
    intermediate_es_cred, alg=ec_alg, typ="entity-statement+jwt"
)
intermediate_es_cred_signed = intermediate_signer_es_cred.sign_compact(
    [intermediate_jwk]
)

intermediate_signer_es_wallet = JWS(
    intermediate_es_wallet, alg=ec_alg, typ="entity-statement+jwt"
)
intermediate_es_wallet_signed = intermediate_signer_es_wallet.sign_compact(
    [intermediate_jwk]
)

ta_es_signer = JWS(ta_es, alg=ec_alg, typ="entity-statement+jwt")
ta_es_signed = ta_es_signer.sign_compact([ta_jwk])

ta_ec_signer = JWS(ta_ec, alg=ec_alg, typ="entity-statement+jwt")
ta_ec_signed = ta_ec_signer.sign_compact([ta_jwk])


trust_chain_issuer = [
    leaf_cred_signed,
    intermediate_es_cred_signed,
    ta_es_signed,
    ta_ec_signed,
]

trust_chain_wallet = [leaf_wallet_signed, intermediate_es_wallet_signed, ta_es_signed]

test_cred = tcv_test.StaticTrustChainValidator(
    trust_chain_issuer, [ta_jwk.serialize()], httpc_params=httpc_params
)
assert test_cred.is_valid

test_wallet = tcv_test.StaticTrustChainValidator(
    trust_chain_wallet, [ta_jwk.serialize()], httpc_params=httpc_params
)
assert test_wallet.is_valid

print(json.dumps(trust_chain_issuer, indent=2))
