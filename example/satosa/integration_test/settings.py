
from cryptojwt.jws.jws import JWS
from cryptojwt.jwk.jwk import key_from_jwk_dict
from pyeudiw.tests.federation.base import (
    NOW,
    EXP,
    leaf_wallet_jwk,
    ta_ec,
    ta_jwk
)

from pyeudiw.tools.utils import iat_now, exp_from_now


RP_EID = "https://localhost/OpenID4VP"

CONFIG_DB = {
    "mongo_db": {
        "storage": {
            "module": "pyeudiw.storage.mongo_storage",
            "class": "MongoStorage",
            "init_params": {
                "url": "mongodb://localhost:27017/",
                "conf": {
                    "db_name": "eudiw",
                    "db_sessions_collection": "sessions",
                    "db_trust_attestations_collection": "trust_attestations",
                    "db_trust_anchors_collection": "trust_anchors"
                },
                "connection_params": {}
            }
        }
    }
}


WALLET_INSTANCE_ATTESTATION = {
    "iss": "https://wallet-provider.example.org",
    "sub": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
    "type": "WalletInstanceAttestation",
    "policy_uri": "https://wallet-provider.example.org/privacy_policy",
    "tos_uri": "https://wallet-provider.example.org/info_policy",
    "logo_uri": "https://wallet-provider.example.org/logo.svg",
    "asc": "https://wallet-provider.example.org/LoA/basic",
    "cnf":
    {
        "jwk": leaf_wallet_jwk.serialize()
    },
    "authorization_endpoint": "eudiw:",
    "response_types_supported": [
        "vp_token"
    ],
    "vp_formats_supported": {
        "jwt_vp_json": {
            "alg_values_supported": ["ES256"]
        },
        "jwt_vc_json": {
            "alg_values_supported": ["ES256"]
        }
    },
    "request_object_signing_alg_values_supported": [
        "ES256"
    ],
    "presentation_definition_uri_supported": False,
    "iat": iat_now(),
    "exp": exp_from_now()
}

rp_jwks = [
    {
        "kty": "RSA",
        "d": "QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7vtyCoA-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVGH9U3W_djh4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q",
        "e": "AQAB",
        "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
        "n": "utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx6nq1uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBKwoxeRyD3zWE2FXRFBbhKGksMrCGnFDsNl5JTlPjaM3kYyImE941ggcuc495m-Fw",
        "p": "2zmGXIMCEHPphw778YjVTar1eycih6fFSJ4I4bl1iq167GqO0PjlOx6CZ1-OdBTVU7HfrYRiUK_BnGRdPDn-DQghwwkB79ZdHWL14wXnpB5y-boHz_LxvjsEqXtuQYcIkidOGaMG68XNT1nM4F9a8UKFr5hHYT5_UIQSwsxlRQ0",
        "q": "2jMFt2iFrdaYabdXuB4QMboVjPvbLA-IVb6_0hSG_-EueGBvgcBxdFGIZaG6kqHqlB7qMsSzdptU0vn6IgmCZnX-Hlt6c5X7JB_q91PZMLTO01pbZ2Bk58GloalCHnw_mjPh0YPviH5jGoWM5RHyl_HDDMI-UeLkzP7ImxGizrM"
    },
    {
        'kty': 'EC',
        'kid': 'xPFTWxeGHTVTaDlzGad0MKN5JmWOSnRqEjJCtvQpoyg',
        'crv': 'P-256',
        'x': 'EkMoe7qPLGMydWO_evC3AXEeXJlLQk9tNRkYcpp7xHo',
        'y': 'VLoHFl90D1SdTTjMvNf3WssWiCBXcU1lGNPbOmcCqdU',
        'd': 'oGzjgBbIYNL9opdJ_rDPnCJF89yN8yj8wegdkYfaxw0'
    }
]
rp_ec = {
    "exp": EXP,
    "iat": NOW,
    "iss": RP_EID,
    "sub": RP_EID,
    'jwks': {"keys": rp_jwks},
    "metadata": {
        "wallet_relying_party": {
            'jwks': {"keys": []}
        },
        "federation_entity": {
            "organization_name": "OpenID Wallet Verifier example",
            "homepage_uri": "https://verifier.example.org/home",
            "policy_uri": "https://verifier.example.org/policy",
            "logo_uri": "https://verifier.example.org/static/logo.svg",
            "contacts": [
                "tech@verifier.example.org"
            ]
        }
    },
    "authority_hints": [
        ta_ec['iss']
    ]
}
rp_signer = JWS(
    rp_ec, alg="RS256",
    typ="application/entity-statement+jwt"
)


_es = ta_es = {
    "exp": EXP,
    "iat": NOW,
    "iss": ta_ec['iss'],
    "sub": RP_EID,
    'jwks': {
        'keys': rp_jwks
    }
}
ta_signer = JWS(
    _es, alg="RS256",
    typ="application/entity-statement+jwt"
)

its_trust_chain = [
    rp_signer.sign_compact([key_from_jwk_dict(rp_jwks[0])]),
    ta_signer.sign_compact([ta_jwk])
]
