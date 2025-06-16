import datetime
from pyeudiw.tests.settings import DEFAULT_X509_LEAF_PRIVATE_KEY, DEFAULT_X509_LEAF_JWK
from pyeudiw.trust.handler.x509 import X509Handler
from pyeudiw.tests.x509.test_x509 import gen_chain
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.trust.handler.exceptions import InvalidTrustHandlerConfiguration
from pyeudiw.tools.utils import iat_now
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from pyeudiw.x509.chain_builder import ChainBuilder
from pyeudiw.x509.crl_builder import CRLBuilder
from requests import Response

def test_wrong_configuration_must_fail():
    try:
        X509Handler(
            client_id="https://test.com",
            leaf_certificate_chains_by_ca={},
            private_keys=[],
            certificate_authorities={}
        )
        assert False, "Should have raised InvalidTrustHandlerConfiguration"
    except InvalidTrustHandlerConfiguration as e:
        assert str(e) == "No x509 certificate chains provided in the configuration"

    try:
        X509Handler(
            client_id="https://test.com",
            leaf_certificate_chains_by_ca={
                "example.com": gen_chain(ca_cn="wrong_example.com", ca_dns="wrong_example.com")
            },
            private_keys=[],
            certificate_authorities={}
        )
        assert False, "Should have raised InvalidTrustHandlerConfiguration"
    except InvalidTrustHandlerConfiguration as e:
        assert "Invalid x509 certificate: expected" in str(e)


def test_extract_trust_material_from_x509_handler():
    chain = gen_chain(leaf_cn="example.com", leaf_dns="example.com", leaf_uri="https://example.com", leaf_private_key=DEFAULT_X509_LEAF_PRIVATE_KEY)

    trust_handler = X509Handler(
        client_id="example.com",
        leaf_certificate_chains_by_ca={
            "ca.example.com": chain
        },
        private_keys=[
            DEFAULT_X509_LEAF_JWK
        ],
        certificate_authorities={
            "ca.example.com": chain[-1]
        }
    )
    trust_source = TrustSourceData.empty("example.com")

    trust_handler.extract_and_update_trust_materials("example.com", trust_source)
    serialized_object = trust_source.serialize()

    assert "x509" in serialized_object
    assert "x5c" in serialized_object["x509"]
    assert len(serialized_object["x509"]["x5c"]) == 3
    assert "expiration_date" in serialized_object["x509"]
    assert serialized_object["x509"]["expiration_date"] > iat_now()
    assert "jwks" in serialized_object["x509"]
    assert serialized_object["x509"]["jwks"][0]["kty"] == "EC"
    assert "x" in serialized_object["x509"]["jwks"][0]
    assert "y" in serialized_object["x509"]["jwks"][0]

def test_fail_if_all_chains_are_invalid():
    invalid_chain = gen_chain(leaf_cn="example.com", date=datetime.datetime.fromisoformat("1990-01-01"))
    try:
        trust_handler = X509Handler(
            client_id="https://example.com",
            leaf_certificate_chains_by_ca={
                "ca.example.com": invalid_chain
            },
            private_keys=[
                DEFAULT_X509_LEAF_JWK
            ],
            certificate_authorities={
                "ca.example.com": invalid_chain[-1]
            }
        )
    except InvalidTrustHandlerConfiguration as e:
        assert True
    except Exception:
        assert False, "Should have raised InvalidTrustHandlerConfiguration due to invalid certificate chain"

def test_chain_crl_passing():
    resp = Response()
    resp.status_code = 200
    resp.headers.update({"Content-Type": "application/x509-crl"})
    resp._content = b"-----BEGIN X509 CRL-----MIIBcjCB+AIBATAKBggqhkjOPQQDAjBHMRwwGgYDVQQDDBMzU2hhcGUgS01TIFJvb3QgMDAxMRYwFAYDVQQLDA1Ob25wcm9kdWN0aW9uMQ8wDQYDVQQKDAYzU2hhcGUXDTIyMDkyMTE1NTA0OFoXDTI3MDkyMDE1NTA0OFowTjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFOBcNMjIwOTIxMTU0OTI1WjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFORcNMjIwOTIxMTU1MDQ4WqAwMC4wHwYDVR0jBBgwFoAUJlmqlqHSmhcu0m7aSgroirdgdWYwCwYDVR0UBAQCAhABMAoGCCqGSM49BAMCA2kAMGYCMQCDRejYgOYC8zC91vqm4D9X4H3IEjKQKfO3vQFd8iE4Q6ao+dBeIZ342nhosnePVxMCMQCHRXwB3eOkIv7u1gzDvu9bXlsWNG8cgR5coTd0re/zRqN7cXuDlkR+h2mQdb0p/Eg=-----END X509 CRL-----"

    chain = ChainBuilder()
    chain.gen_certificate(
        cn="ca.example.com",
        org_name="Example CA",
        country_name="IT",
        dns="ca.example.com",
        date=datetime.datetime.now(),
        uri="https://ca.example.com",
        crl_distr_point="http://ca.example.com/crl.pem",
        ca=True,
        path_length=1,
    )
    chain.gen_certificate(
        cn="intermediate.example.com",
        org_name="Example Intermediate",
        country_name="IT",
        dns="intermediate.example.com",
        uri="https://intermediate.example.com",
        date=datetime.datetime.now(),
        ca=True,
        path_length=0,
    )
    chain.gen_certificate(
        cn="example.com",
        org_name="Example Leaf",
        country_name="IT",
        dns="example.com",
        uri="https://example.com",
        date=datetime.datetime.now(),
        private_key=DEFAULT_X509_LEAF_PRIVATE_KEY,
        ca=False,
        path_length=None,
    )

    chain = chain.get_chain("DER")
    
    trust_handler = X509Handler(
        client_id="example.com",
        leaf_certificate_chains_by_ca={
            "ca.example.com": chain
        },
        private_keys=[
            DEFAULT_X509_LEAF_JWK
        ],
        certificate_authorities={
            "ca.example.com": chain[-1]
        }
    )
    trust_source = TrustSourceData.empty("example.com")

    mock_staus_list_endpoint = patch(
        "pyeudiw.x509.crl_helper.http_get_sync",
        return_value=[
            resp
        ],
    )

    mock_staus_list_endpoint.start()
    trust_handler.extract_and_update_trust_materials("example.com", trust_source)
    mock_staus_list_endpoint.stop()
    serialized_object = trust_source.serialize()

    assert "x509" in serialized_object
    assert "crls" in serialized_object["x509"]
    assert len(serialized_object["x509"]["crls"]) == 1

def test_chain_crl_fail():
    resp = Response()
    resp.status_code = 200
    resp.headers.update({"Content-Type": "application/x509-crl"})

    ca_key = ec.generate_private_key(
        ec.SECP256R1(),
    )

    crl = CRLBuilder(
        issuer="ca.example.com",
        private_key=ca_key,
    )
    crl.add_revoked_certificate(
        serial_number=44442,
        revocation_date=datetime.datetime.fromisoformat("2022-09-21T15:49:25"),
    )

    resp._content = crl.to_pem()

    chain = ChainBuilder()
    chain.gen_certificate(
        cn="ca.example.com",
        org_name="Example CA",
        country_name="IT",
        dns="ca.example.com",
        date=datetime.datetime.now(),
        uri="https://ca.example.com",
        crl_distr_point="http://ca.example.com/crl.pem",
        private_key=ca_key,
        ca=True,
        path_length=1,
    )
    chain.gen_certificate(
        cn="intermediate.example.com",
        org_name="Example Intermediate",
        country_name="IT",
        dns="intermediate.example.com",
        uri="https://intermediate.example.com",
        date=datetime.datetime.now(),
        ca=True,
        path_length=0,
        serial_number=44442,
    )
    chain.gen_certificate(
        cn="example.com",
        org_name="Example Leaf",
        country_name="IT",
        dns="example.com",
        uri="https://example.com",
        date=datetime.datetime.now(),
        private_key=DEFAULT_X509_LEAF_PRIVATE_KEY,
        ca=False,
        path_length=None,
    )

    chain = chain.get_chain("DER")
    
    try:
        trust_handler = X509Handler(
            client_id="https://example.com",
            leaf_certificate_chains_by_ca={
                "ca.example.com": chain
            },
            private_keys=[
                DEFAULT_X509_LEAF_JWK
            ],
            certificate_authorities={
                "ca.example.com": chain[-1]
            }
        )
    except InvalidTrustHandlerConfiguration as e:
        assert True
    except Exception:
        assert False, "Should have raised InvalidTrustHandlerConfiguration due to revoked certificate"
