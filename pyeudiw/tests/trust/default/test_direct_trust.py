import unittest.mock

from pyeudiw.trust.default import DEFAULT_DIRECT_TRUST_PARAMS
from pyeudiw.trust.default.direct_trust import DirectTrustSdJwtVc

from pyeudiw.tests.trust.default.settings import issuer, jwt_vc_issuer_endpoint_response
from pyeudiw.tests.trust.default.settings import issuer_jwk as expected_jwk


def test_direct_trust_jwk():
    mocked_issuer_jwt_vc_issuer_endpoint = unittest.mock.patch("pyeudiw.vci.jwks_provider.get_http_url", return_value=[jwt_vc_issuer_endpoint_response])
    mocked_issuer_jwt_vc_issuer_endpoint.start()

    trust_source = DirectTrustSdJwtVc(**DEFAULT_DIRECT_TRUST_PARAMS)
    obtained_jwks = trust_source.get_public_keys(issuer)

    mocked_issuer_jwt_vc_issuer_endpoint.stop()

    assert len(obtained_jwks) == 1, f"expected 1 jwk, obtained {len(obtained_jwks)}"
    assert expected_jwk == obtained_jwks[0]
