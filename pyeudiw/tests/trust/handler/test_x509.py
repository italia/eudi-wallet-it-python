import datetime
from pyeudiw.tests.settings import DEFAULT_X509_LEAF_PRIVATE_KEY, DEFAULT_X509_LEAF_JWK
from pyeudiw.trust.handler.x509 import X509Handler
from pyeudiw.tests.x509.test_x509 import gen_chain
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.trust.handler.exceptions import InvalidTrustHandlerConfiguration

def test_wrong_configuration_must_fail():
    try:
        X509Handler(
            client_id="https://test.com",
            relying_party_certificate_chains_by_ca={},
            private_keys=[],
            certificate_authorities={}
        )
        assert False, "Should have raised InvalidTrustHandlerConfiguration"
    except InvalidTrustHandlerConfiguration as e:
        assert str(e) == "No x509 certificate chains provided in the configuration"

    try:
        X509Handler(
            client_id="https://test.com",
            relying_party_certificate_chains_by_ca={
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
        client_id="https://example.com",
        relying_party_certificate_chains_by_ca={
            "ca.example.com": chain
        },
        private_keys=[
            DEFAULT_X509_LEAF_JWK
        ],
        certificate_authorities={
            "ca.example.com": chain[-1]
        }
    )
    trust_source = TrustSourceData.empty("https://example.com")

    trust_handler.extract_and_update_trust_materials("https://example.com", trust_source)
    serialized_object = trust_source.serialize()

    assert "x509" in serialized_object
    assert "x5c" in serialized_object["x509"]
    assert len(serialized_object["x509"]["x5c"]) == 3
    assert "expiration_date" in serialized_object["x509"]
    assert serialized_object["x509"]["expiration_date"] > datetime.datetime.now()
    assert "jwks" in serialized_object["x509"]
    assert serialized_object["x509"]["jwks"][0]["kty"] == "EC"
    assert "x" in serialized_object["x509"]["jwks"][0]
    assert "y" in serialized_object["x509"]["jwks"][0]

def test_return_nothing_if_chain_is_invalid():
    invalid_chain = gen_chain(leaf_cn="example.com", date=datetime.datetime.fromisoformat("1990-01-01"))
    trust_handler = X509Handler(
        client_id="https://example.com",
        relying_party_certificate_chains_by_ca={
            "ca.example.com": invalid_chain
        },
        private_keys=[
            DEFAULT_X509_LEAF_JWK
        ],
        certificate_authorities={
            "ca.example.com": invalid_chain[-1]
        }
    )
    trust_source = TrustSourceData.empty("https://example.com")

    trust_handler.extract_and_update_trust_materials("https://example.com", trust_source)
    serialized_object = trust_source.serialize()

    assert "x509" not in serialized_object
