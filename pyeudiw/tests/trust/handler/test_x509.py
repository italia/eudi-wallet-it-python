import datetime
import unittest.mock
from pyeudiw.trust.handler.x509 import X509Hanlder
from pyeudiw.tests.x509.test_x509 import gen_chain, chain_to_pem
from pyeudiw.trust.model.trust_source import TrustSourceData

def test_direct_trust_extract_jwks_from_jwk_metadata_by_reference():
    trust_handler = X509Hanlder("https://example.com")
    trust_source = TrustSourceData.empty("https://example.com")

    mocked_x509_certificate = unittest.mock.patch(
        "pyeudiw.trust.handler.x509.ssl.get_server_certificate",
        return_value=chain_to_pem(gen_chain()),
    )

    mocked_x509_certificate.start()
    trust_handler.extract_and_update_trust_materials("https://example.com", trust_source)
    mocked_x509_certificate.stop()

    serialized_object = trust_source.serialize()

    assert "x509" in serialized_object
    assert "x5c" in serialized_object["x509"]
    assert len(serialized_object["x509"]["x5c"]) == 3
    assert "expiration_date" in serialized_object["x509"]
    assert serialized_object["x509"]["expiration_date"] > datetime.datetime.now()
    assert "jwks" in serialized_object["x509"]
    assert serialized_object["x509"]["jwks"][0]["kty"] == "RSA"
    assert "n" in serialized_object["x509"]["jwks"][0]

