import unittest.mock

from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustJWTHandler
from pyeudiw.tests.trust.handler import issuer
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.tests.trust.handler import issuer_jwk as expected_jwk


def test_direct_trust_jwk():
    mocked_issuer_jwt_vc_issuer_endpoint = unittest.mock.patch("pyeudiw.vci.jwks_provider.RemoteVciJwksSource.get_jwks", return_value=[expected_jwk])
    mocked_issuer_jwt_vc_issuer_endpoint.start()

    trust_source = DirectTrustJWTHandler()

    trust_source_data = TrustSourceData(entity_id=issuer)
    trust_source.extract(issuer, trust_source_data)
    obtained_jwks = trust_source_data.keys

    mocked_issuer_jwt_vc_issuer_endpoint.stop()

    assert len(obtained_jwks) == 1, f"expected 1 jwk, obtained {len(obtained_jwks)}"
    assert expected_jwk == obtained_jwks[0]
