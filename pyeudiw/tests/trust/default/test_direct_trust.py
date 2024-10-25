from dataclasses import dataclass
import json
import unittest.mock

import requests

from pyeudiw.tools.utils import _lru_cached_get_http_url
from pyeudiw.trust.default import DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS
from pyeudiw.trust.default.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc, InvalidJwkMetadataException

from pyeudiw.tests.trust.default.settings import issuer, jwt_vc_issuer_endpoint_response
from pyeudiw.tests.trust.default.settings import issuer_jwk as expected_jwk


def test_direct_trust_build_issuer_jwk_endpoint():
    entity_id = "https://credential-issuer.example/vct"
    well_known_component = "/.well-known/jwt-vc-issuer"
    expected_url = "https://credential-issuer.example/.well-known/jwt-vc-issuer/vct"
    obtained_url = DirectTrustSdJwtVc.build_issuer_jwk_endpoint(entity_id, well_known_component)
    assert expected_url == obtained_url


def test_direct_trust_build_issuer_metadata_endpoint():
    @dataclass
    class TestCase:
        entity_id: str
        expected: str
        explanation: str

    test_cases: list[TestCase] = [
        TestCase(
            "https://entity-id.example/path",
            "https://entity-id.example/path/.well-known/openid-credential-issuer",
            explanation="the entity id does NOT have a trailing path separator"
        ),
        TestCase(
            "https://entity-id.example/path/",
            "https://entity-id.example/path/.well-known/openid-credential-issuer",
            explanation="the entity id DOES have a trailing path separator"
        )
    ]

    metadata_endpoint = "/.well-known/openid-credential-issuer"
    for i, case in enumerate(test_cases):
        obtained = DirectTrustSdJwtVc.build_issuer_metadata_endpoint(case.entity_id, metadata_endpoint)
        assert case.expected == obtained, f"failed case {i}: {case.explanation}"


def test_direct_trust_extract_jwks_from_jwk_metadata_by_value():
    trust_source = DirectTrustSdJwtVc()
    jwk_metadata = {
        "issuer": issuer,
        "jwks": {
            "keys": [
                expected_jwk
            ]
        }
    }
    obt_jwks = trust_source._extract_jwks_from_jwk_metadata(jwk_metadata)
    exp_jwks = {
        "keys": [
            expected_jwk
        ]
    }
    assert obt_jwks == exp_jwks


def test_direct_trust_extract_jwks_from_jwk_metadata_by_reference():
    trust_source = DirectTrustSdJwtVc()
    jwk_metadata = {
        "issuer": issuer,
        "jwks_uri": issuer + "jwks"
    }
    expected_jwks = {
        "keys": [
            expected_jwk
        ]
    }
    jwks_uri_response = requests.Response()
    jwks_uri_response.status_code = 200
    jwks_uri_response.headers.update({"Content-Type": "application/json"})
    jwks_uri_response._content = json.dumps(expected_jwks).encode('utf-8')

    mocked_jwks_document_endpoint = unittest.mock.patch(
        "pyeudiw.trust.default.direct_trust_sd_jwt_vc.get_http_url",
        return_value=[jwks_uri_response]
    )
    mocked_jwks_document_endpoint.start()
    obtained_jwks = trust_source._extract_jwks_from_jwk_metadata(jwk_metadata)
    mocked_jwks_document_endpoint.stop()

    assert expected_jwks == obtained_jwks


def test_direct_trust_extract_jwks_from_jwk_metadata_invalid():
    trust_source = DirectTrustSdJwtVc()
    jwk_metadata = {
        "issuer": issuer
    }
    try:
        trust_source._extract_jwks_from_jwk_metadata(jwk_metadata)
        assert False, "parsed invalid metadata: should have raised InvalidJwkMetadataException instead"
    except InvalidJwkMetadataException:
        assert True


def test_direct_trust_jwk():
    trust_source = DirectTrustSdJwtVc(**DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS)

    mocked_issuer_jwt_vc_issuer_endpoint = unittest.mock.patch(
        "pyeudiw.trust.default.direct_trust_sd_jwt_vc.get_http_url",
        return_value=[jwt_vc_issuer_endpoint_response]
    )
    mocked_issuer_jwt_vc_issuer_endpoint.start()
    obtained_jwks = trust_source.get_public_keys(issuer)
    mocked_issuer_jwt_vc_issuer_endpoint.stop()

    assert len(obtained_jwks) == 1, f"expected 1 jwk, obtained {len(obtained_jwks)}"
    assert expected_jwk == obtained_jwks[0]


def test_direct_trust_cache():
    cache_ttl = 60*60*24*365  # 1 year
    tries = 5
    trust_source = DirectTrustSdJwtVc(cache_ttl=cache_ttl, **DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS)

    mocked_issuer_jwt_vc_issuer_endpoint = unittest.mock.patch(
        "pyeudiw.tools.utils.get_http_url",
        return_value=[jwt_vc_issuer_endpoint_response]
    )
    mocked_issuer_jwt_vc_issuer_endpoint.start()
    for _ in range(tries):
        obtained_jwks = trust_source.get_public_keys(issuer)
        assert len(obtained_jwks) == 1, f"expected 1 jwk, obtained {len(obtained_jwks)}"
        assert expected_jwk == obtained_jwks[0]
    mocked_issuer_jwt_vc_issuer_endpoint.stop()

    cache_misses = _lru_cached_get_http_url.cache_info().misses
    exp_cache_misses = 1
    cache_hits = _lru_cached_get_http_url.cache_info().hits
    exp_cache_hits = tries - 1
    assert cache_misses == exp_cache_misses, f"cache missed more that {exp_cache_misses} time: {cache_misses}"
    assert cache_hits == exp_cache_hits, f"cache hit less than {exp_cache_hits} times: {cache_hits}"
