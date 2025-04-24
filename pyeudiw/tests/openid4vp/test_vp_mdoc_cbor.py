from ssl import DER_cert_to_PEM_cert
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pyeudiw.storage.db_engine import DBEngine
from requests import Response
from unittest.mock import patch
from pyeudiw.openid4vp.vp_mdoc_cbor import VpMDocCbor
from pyeudiw.tests.settings import (
    CONFIG,
    BASE_URL,
    DEFAULT_X509_CHAIN,
    jwk
)

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
         "x509": {
            "module": "pyeudiw.trust.handler.x509",
            "class": "X509Handler",
            "config": {
                "client_id": f"{BASE_URL}/OpenID4VP",
                "relying_party_certificate_chains_by_ca":{
                    "ca.example.com": DEFAULT_X509_CHAIN,
                },
                "certificate_authorities": {
                    "ca.example.com": DER_cert_to_PEM_cert(DEFAULT_X509_CHAIN[-1]),
                    "https://credential-issuer.example.org": "-----BEGIN CERTIFICATE-----\nMIIB/jCCAaSgAwIBAgIUUMBi34bUh6gnoMbxypdmBk/JeUMwCgYIKoZIzj0EAwIw\nZDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNh\nbiBGcmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxEzARBgNVBAMMCm15c2l0\nZS5jb20wHhcNMjUwMzI1MTQyMTE0WhcNMjUwNDA0MTQyMTE0WjBkMQswCQYDVQQG\nEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNj\nbzETMBEGA1UECgwKTXkgQ29tcGFueTETMBEGA1UEAwwKbXlzaXRlLmNvbTBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABEXbtJ1tl7OFv1FF4q3BSy7kFlDUxvdQr03c\ncT72OoZw/BR+q735qhltuHSuDeAt5O7yNbSbS0KQbQvf4HQWzDujNDAyMDAGA1Ud\nEQQpMCeGJWh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5vcmcwCgYI\nKoZIzj0EAwIDSAAwRQIgFgMjgF11XRv0E1rtNmWWOarprjbmu6tqOsulAMFXxV4C\nIQDrpFoPCc2uDlEY4BzS10prwAgonpZeg/lm8/ll0IjVkQ==\n-----END CERTIFICATE-----\n"
                },
                "private_keys": [
                    jwk,
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": "123114cf-ebef-48d9-9602-3be85e6e12dd",
                        "d": "b41VkvQv083zdtsqX9Q4RqW6DOH7LcSMSSK-KaUi-jtR4SdPkans1vY9QwfZ1gL-iQm0UP50Txow1Xawnh_-O45efpTOJ0sEXno5gXregQQNXxum-ATh7npYTv3Zjfl1lw4GX9UvXwtko3zHA01OtvOdXxtDHtatvoojFEwTisBT5j9f_q7Dmmgmtml17U_M1heANv9O9PqOey2U7_wZRji2lLGpeP7DxeBpTVztyKdnBZCjBnwfyrES3eAPlO5GI3zWAxHuaSsms3F8WQKJqHQs8xDxHpC1MCPMqmnCZnrBxZXxeeg6gMuEJ72RtzziOwH2gr3alND6gpARwwgEYQ",
                        "n": "oV1dBQQpxKhVpJzouceEvuJQ_0nIvK3GVF4FEKRunCWK1amBupkegZgIXq98WsvfNHLwKPhhFXO1unONb44Q51VeFet7ThWyJSB9dhXmr21wvqFA4HVQj4vGPLiGUmacKL-9W4vd_ElLyf1TEtcolUafEI83zfg6bsVkJrwdSRDkxYU5Kh28ayCgoaqXUwLsuR-xT5EiksJESHtqW5_8sqrp5v95UOxxK8NdbEQ54Fr2pfeKQ6Id5VyUlwOnfnV6zgJJ7qBM1NxcyQ7OkQHrh03LfoPF2Hl7-EuZ0ET8p9RVC7eC2NH033O9rSiWljwwsvmRG7nyVN7bkB5wbInp0Q",
                        "e": "AQAB",
                        "p": "0RHnCQZiI6VomMmRcfDyRgqZjUEHLPF17u4TAxqFys3-lgxuRCn8cjXkzJ7t9C0FmGNQy2zrwhQZRUlKotPwB9t0qTRwshqmG40O4EHfdgqu_sqNe8toCJ9xGqkDJFdYvmPy-SkqMYyszRf1GEwMjgj1Ncyx4WciaEbHZUllQo0",
                        "q": "xZYanwkJJGOD4b7Z2PwCA_ubEYU8O2C3UoeINv2P5fXicXRK278o4WelaQBhyvDcPyS3lJyyusB_ro3Fax1fm4IDV1buITar671NzooWKOUQgG0MoVHS8k7qFmGXGDhFBrO_khsvc3FNAjdqkNpH5slo8AwvN2SrbHO3GX6aVVU",
                        "dp": "tk7iJCCI24SVXQYH6k-tNB5yH5ag5zP3Hs5DjeVG3b4bTkSwsofaNs2AIl5EKTRJOMUB4yGrw6U7FAwBJVOib3eSlym_S8-pIUUzv6IxdgGC73M5RMXuhfZi7liLANmZ7QvDCDo5LNP6qy1E8FcAa6qsCKniQydn_X4aydvijNE",
                        "dq": "Ml9mQg1Hq2NDiBXj7BGzYdiPXBQfmvO5SO0MqRhTy0i4hjwjqYo-ndiSrwZN6DMns2Fk_BpG5p2U76dtITXH3hlzSJz88LLDecI1R-akZ6CeaF9kzOvTX7sGqtYOczpFPsQsns8XddL40wvVu0Aq_Id0nV49211q5qdJktJX_lE",
                        "qi": "rQ5SbqNeVrGOZ1rJXWbiAxux_-E1HBunOKWN6HQpoStLpRzJ6zz8aEXhSXMAnbeQOi1ZBS1escmlSupkgz4TEnrhionAJ2orIJ1rOiZIii7stJVkB3fs2LBoxs17Msj9AVrBA-tHhWpoBj63t-ahhEuxhgReq_0DjzQgcP7xUA"
                    },
                ]
            }
        },
    },
    DBEngine(CONFIG["storage"]),
    default_client_id="default-client-id",
)

resp = Response()
resp.status_code = 200
resp.headers.update({"Content-Type": "application/statuslist+cwt"})
resp._content = b"d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d584027d5535dfe0a33291cc9bfb41053ad2493c49d1ee4635e12548a79bac92916845fee76799c42762f928441c5c344e3612381e0cf88f2f160b3e1f97728ec8403"

mock_staus_list_endpoint = patch(
    "pyeudiw.status_list.helper.http_get_sync",
    return_value=[
        resp
    ],
)

def issue_mdoc_cbor(status_list: bool = False, idx: int = 1):
    PKEY = {
        'KTY': 'EC2',
        'CURVE': 'P_256',
        'ALG': 'ES256',
        'D': b"<\xe5\xbc;\x08\xadF\x1d\xc5\x0czR'T&\xbb\x91\xac\x84\xdc\x9ce\xbf\x0b,\x00\xcb\xdd\xbf\xec\xa2\xa5",
        'KID': b"demo-kid"
    }

    PID_DATA = {
        "eu.europa.ec.eudiw.pid.1": {
            "family_name": "Raffaello",
            "given_name": "Mascetti",
            "birth_date": "1922-03-13",
            "birth_place": "Rome",
            "birth_country": "IT"
        },
        "eu.europa.ec.eudiw.pid.it.1": {
            "tax_id_code": "TINIT-XXXXXXXXXXXXXXX"
        }
    }

    status = None

    if status_list:
        status = {
            "status_list": {
                "idx": idx,
                "uri": "https://example.com/statuslists/1"
            }
        }

    mdoci = MdocCborIssuer(
        private_key=PKEY,
        alg="ES256",
    )

    mdoci.new(
        doctype="eu.europa.ec.eudiw.pid.1",
        data=PID_DATA,
        validity={
            "issuance_date": "2024-12-31",
            "expiry_date": "2050-12-31"
        },
        status=status,
    )

    return mdoci.dumps().decode()

def test_handler_initialization():
    ps = VpMDocCbor(
        trust_evaluator=trust_ev, 
    )

    assert isinstance(ps, VpMDocCbor), "Handler for 'vp_mdoc_cbor' format is incorrect."

def test_handler_correct_parsing():
    ps = VpMDocCbor(
        trust_evaluator=trust_ev, 
    )

    vp_token = issue_mdoc_cbor()
    parsed_tokens = ps.parse(vp_token)
    
    assert parsed_tokens == {
        "eu.europa.ec.eudiw.pid.1": {
            "family_name": "Raffaello",
            "given_name": "Mascetti",
            "birth_date": "1922-03-13",
            "birth_place": "Rome",
            "birth_country": "IT"
        },
        "eu.europa.ec.eudiw.pid.it.1": {
            "tax_id_code": "TINIT-XXXXXXXXXXXXXXX"
        }
    }, f"Parsed tokens are not correct: {parsed_tokens}"

def test_handler_correct_validation():
    ps = VpMDocCbor(
        trust_evaluator=trust_ev, 
    )

    vp_token = issue_mdoc_cbor()

    ps.validate(
        vp_token, 
        "https://example.com/", 
        "1234567890"
    )

def test_handler_correct_validation_with_status_list():
    ps = VpMDocCbor(
        trust_evaluator=trust_ev, 
    )

    vp_token = issue_mdoc_cbor(status_list=True)

    mock_staus_list_endpoint.start()
    ps.validate(
        vp_token, 
        "https://example.com/", 
        "1234567890"
    )
    mock_staus_list_endpoint.stop()

def test_handler_correct_validation_with_status_list_revoked():
    ps = VpMDocCbor(
        trust_evaluator=trust_ev, 
    )

    vp_token = issue_mdoc_cbor(status_list=True, idx=0)

    try:
        mock_staus_list_endpoint.start()

        ps.validate(
            vp_token, 
            "https://example.com/", 
            "1234567890"
        )

        assert False, "Validation should have failed with revoked status list."
    except Exception as e:
        assert str(e) == "Status list indicates that the token is revoked", "Incorrect exception message."
    finally:
        mock_staus_list_endpoint.stop()