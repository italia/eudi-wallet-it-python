import uuid
from pyeudiw.openid4vp.vp_sd_jwt_vc import VpVcSdJwtParserVerifier
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.settings import CONFIG
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.sd_jwt.holder import SDJWTHolder
from pyeudiw.jwt.jws_helper import DEFAULT_SIG_KTY_MAP
from unittest.mock import patch
from pyeudiw.tests.federation.base import (
    leaf_cred_jwk,
    leaf_wallet_jwk,
    trust_chain_issuer,
    ta_jwk
)
from pyeudiw.tests.settings import (
    CONFIG,
    CREDENTIAL_ISSUER_CONF,
    CREDENTIAL_ISSUER_ENTITY_ID,
    _METADATA,
    jwk
)
from pyeudiw.sd_jwt.utils.yaml_specification import _yaml_load_specification
from requests import Response

def issue_sd_jwt(aud: str, nonce: str, status_list: bool = False, idx: int = 1, invalid_trust_chain: bool = False) -> dict:
    settings = CREDENTIAL_ISSUER_CONF
    settings['issuer'] = CREDENTIAL_ISSUER_ENTITY_ID
    settings['default_exp'] = CONFIG['jwt']['default_exp']

    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": exp_from_now(settings["default_exp"])  # in seconds
    }

    issuer_jwk = leaf_cred_jwk.serialize(private=True)
    holder_jwk = leaf_wallet_jwk.serialize(private=True)

    specification = _yaml_load_specification(
        settings["sd_specification"])
    
    if status_list:
        specification["status"] = {
            "status_list": {
                "idx": idx,
                "uri": "https://example.com/statuslists/1"
            }
        }
        
    specification.update(claims)
    use_decoys = specification.get("add_decoy_claims", True)

    additional_headers = {
        "trust_chain": trust_chain_issuer if not invalid_trust_chain else trust_chain_issuer[::-1],
    }

    additional_headers['kid'] = issuer_jwk["kid"]

    sdjwt_at_issuer = SDJWTIssuer(
        user_claims=specification,
        issuer_keys=[issuer_jwk],
        holder_key=holder_jwk,
        add_decoy_claims=use_decoys,
        extra_header_parameters=additional_headers
    )


    sdjwt_at_holder = SDJWTHolder(
        sdjwt_at_issuer.sd_jwt_issuance,
        serialization_format="compact",
    )

    sdjwt_at_holder.create_presentation(
        {},
        nonce,
        aud,
        holder_key=holder_jwk,
        sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk["kty"]],
    )

    return sdjwt_at_holder.sd_jwt_presentation


trust_ev = CombinedTrustEvaluator.from_config(
    {
        "direct_trust_sd_jwt_vc": {
            "module": "pyeudiw.trust.handler.direct_trust_sd_jwt_vc",
            "class": "DirectTrustSdJwtVc",
            "config": {
                "jwk_endpoint": "/.well-known/jwt-vc-issuer",
                "httpc_params": {"connection": {"ssl": True}, "session": {"timeout": 6}},
            },
        },
        "federation": {
            "module": "pyeudiw.trust.handler.federation",
            "class": "FederationHandler",
            "config": {
                "entity_configuration_exp": 600,
                "metadata": _METADATA,
                "metadata_type": "openid_credential_verifier",
                "authority_hints": ["https://trust-anchor.example.org"],
                "trust_anchors": {
                    "https://trust-anchor.example.org": [
                        ta_jwk.serialize(private=False),
                    ]
                },
                "default_sig_alg": "RS256",
                "federation_jwks": [
                    jwk,
                    {
                        "kty": "RSA",
                        "d": "QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7v"
                        "tyCoA-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVG"
                        "H9U3W_djh4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q",
                        "e": "AQAB",
                        "kid": "9Cquk0X-fNPSdePQIgQcQZtD6J0IjIRrFigW2PPK_-w",
                        "n": "utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx"
                        "6nq1uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBK"
                        "woxeRyD3zWE2FXRFBbhKGksMrCGnFDsNl5JTlPjaM3kYyImE941ggcuc495m-Fw",
                        "p": "2zmGXIMCEHPphw778YjVTar1eycih6fFSJ4I4bl1iq167GqO0PjlOx6CZ1-OdBTVU7HfrYRiUK_BnGRdPDn-DQghwwkB79ZdHWL14wXnpB5y-boHz_LxvjsEqXtuQYcIkidOGaMG6"
                        "8XNT1nM4F9a8UKFr5hHYT5_UIQSwsxlRQ0",
                        "q": "2jMFt2iFrdaYabdXuB4QMboVjPvbLA-IVb6_0hSG_-EueGBvgcBxdFGIZaG6kqHqlB7qMsSzdptU0vn6IgmCZnX-Hlt6c5X7JB_q91PZMLTO01pbZ2Bk58GloalCHnw_mjPh0YPvi"
                        "H5jGoWM5RHyl_HDDMI-UeLkzP7ImxGizrM",
                    },
                    {
                        "kty": "EC",
                        "kid": "xPFTWxeGHTVTaDlzGad0MKN5JmWOSnRqEjJCtvQpoyg",
                        "crv": "P-256",
                        "x": "EkMoe7qPLGMydWO_evC3AXEeXJlLQk9tNRkYcpp7xHo",
                        "y": "VLoHFl90D1SdTTjMvNf3WssWiCBXcU1lGNPbOmcCqdU",
                        "d": "oGzjgBbIYNL9opdJ_rDPnCJF89yN8yj8wegdkYfaxw0",
                    },
                ],
                "trust_marks": ["..."],
                "federation_entity_metadata": {
                    "organization_name": "Example RP",
                    "homepage_uri": "https://developers.italia.it",
                    "policy_uri": "https://developers.italia.it/privacy-policy",
                    "tos_uri": "https://developers.italia.it/privacy-policy",
                    "logo_uri": "https://developers.italia.it/assets/img/io-it-logo-white.svg",
                },
            },
        },
    },
    DBEngine(CONFIG["storage"]),
    default_client_id="default-client-id",
)

resp = Response()
resp.status_code = 200
resp.headers.update({"Content-Type": "application/statuslist+jwt"})
resp._content = b"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.eyJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQWhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3RhdHVzbGlzdHMvMSIsInR0bCI6NDMyMDB9.2RSRdUce0QmRvsbJkt0Hr0Ny5c9Tim2yj43wMFU76xjv9TClW5-B65b9pZSraeoPv6OxTULb4dHiWK0O8oLi6g"

mock_staus_list_endpoint = patch(
    "pyeudiw.status_list.helper.http_get_sync",
    return_value=[
        resp
    ],
)

def test_handler_initialization():
    ps = VpVcSdJwtParserVerifier(
        trust_evaluator=trust_ev, 
        sig_alg_supported=["ES256", "ES384", "ES512"]
    )

    assert isinstance(ps, VpVcSdJwtParserVerifier), "Handler for 'vp_sd_jwt_vc' format is incorrect."

def test_handler_correct_parsing():
    nonce = str(uuid.uuid4())
    aud = str(uuid.uuid4())

    ps = VpVcSdJwtParserVerifier(
        trust_evaluator=trust_ev, 
        sig_alg_supported=["ES256", "ES384", "ES512"]
    )

    vp_token = issue_sd_jwt(aud, nonce)
    parsed_tokens = ps.parse(vp_token)
    
    assert parsed_tokens['holder_disclosed_claims'] == {
        'given_name': 'Mario', 
        'family_name': 'Rossi', 
        'place_of_birth': {
            'country': 'IT', 
            'locality': 'Rome'
        }
    }

    assert parsed_tokens['key_binding'] is True, "Key binding is not present."
    assert parsed_tokens['iss'] == 'https://issuer.example.com', "Issuer is not correct."


def test_handler_correct_validation():
    nonce = str(uuid.uuid4())
    aud = str(uuid.uuid4())

    ps = VpVcSdJwtParserVerifier(
        trust_evaluator=trust_ev, 
        sig_alg_supported=["ES256", "ES384", "ES512"]
    )

    vp_token = issue_sd_jwt(aud, nonce)

    ps.validate(
        vp_token, 
        aud, 
        nonce
    )
    
   
def test_handler_correct_validation_with_status_list():
    nonce = str(uuid.uuid4())
    aud = str(uuid.uuid4())

    ps = VpVcSdJwtParserVerifier(
        trust_evaluator=trust_ev, 
        sig_alg_supported=["ES256", "ES384", "ES512"]
    )

    vp_token = issue_sd_jwt(aud, nonce, True)

    mock_staus_list_endpoint.start()
    ps.validate(
        vp_token, 
        aud, 
        nonce
    )
    mock_staus_list_endpoint.stop()


def test_handler_failed_validation_with_status_list():
    nonce = str(uuid.uuid4())
    aud = str(uuid.uuid4())

    ps = VpVcSdJwtParserVerifier(
        trust_evaluator=trust_ev, 
        sig_alg_supported=["ES256", "ES384", "ES512"]
    )

    vp_token = issue_sd_jwt(aud, nonce, True, idx = 0)

    try:
        mock_staus_list_endpoint.start()
        ps.validate(
            vp_token, 
            aud, 
            nonce
        )
        assert False, "Validation should have failed."
    except Exception as e:
        assert str(e) == "Status list indicates that the token is revoked", "Incorrect exception message."
    finally:
        mock_staus_list_endpoint.stop()

def test_handler_failed_validation():
    nonce = str(uuid.uuid4())
    aud = str(uuid.uuid4())

    ps = VpVcSdJwtParserVerifier(
        trust_evaluator=trust_ev, 
        sig_alg_supported=["ES256", "ES384", "ES512"]
    )

    vp_token = issue_sd_jwt(aud, nonce, invalid_trust_chain=True)

    try:
        ps.validate(
            vp_token, 
            aud, 
            nonce
        )
        assert False, "Validation should have failed."
    except Exception as e:
        assert str(e) == "Unknown Trust Anchor: 'https://credential-issuer.example.org' is not a recognizable Trust Anchor.", "Incorrect exception message."
    