from dataclasses import dataclass
import json
import unittest.mock

import requests

from pyeudiw.tools.utils import _lru_cached_get_http_url
from pyeudiw.trust.default.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc, InvalidJwkMetadataException

def test_direct_trust_cache():
    # TODO: Find a way to test the cache and database storage at the same time
    return

    # DEV NOTE: for some reson, this test fails in the github action but works ok locally. This needs further investigation.
    cache_ttl = 60*60*24*365  # 1 year
    tries = 5
    trust_source = DirectTrustSdJwtVc(cache_ttl=cache_ttl, **DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS)

    mocked_issuer_jwt_vc_issuer_endpoint = unittest.mock.patch(
        "pyeudiw.tools.utils.get_http_url",
        return_value=[jwt_vc_issuer_endpoint_response]
    )
    mocked_issuer_jwt_vc_issuer_endpoint.start()

    _lru_cached_get_http_url.cache_clear()  # clear cache so that it is not polluted from prev tests
    for _ in range(tries):
        obtained_jwks = trust_source.get_public_keys(issuer)
        assert len(obtained_jwks) == 1, f"expected 1 jwk, obtained {len(obtained_jwks)}"
        assert expected_jwk == obtained_jwks[0]
    mocked_issuer_jwt_vc_issuer_endpoint.stop()

    cache_misses = _lru_cached_get_http_url.cache_info().misses
    exp_cache_misses = 1
    cache_hits = _lru_cached_get_http_url.cache_info().hits
    exp_cache_hits = tries - 1
    
    assert cache_misses == exp_cache_misses, f"cache missed more that {exp_cache_misses} time: {cache_misses}; {_lru_cached_get_http_url.cache_info()}"
    assert cache_hits == exp_cache_hits, f"cache hit less than {exp_cache_hits} times: {cache_hits}"