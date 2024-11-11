import unittest.mock

from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.tests.trust.handler import issuer
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.tests.trust.handler import issuer_jwk as expected_jwk
from dataclasses import dataclass
import requests
import json
from pyeudiw.trust.handler.exception import InvalidJwkMetadataException
from pyeudiw.tests.trust.handler import jwt_vc_issuer_endpoint_response, _generate_response
import uuid

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
        "pyeudiw.trust.handler.direct_trust_sd_jwt_vc.get_http_url",
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
    trust_handler = DirectTrustSdJwtVc()

    random_issuer = f"{uuid.uuid4()}.issuer.it"

    mocked_issuer_jwt_vc_issuer_endpoint = unittest.mock.patch(
        "pyeudiw.trust.handler.direct_trust_sd_jwt_vc.get_http_url",
        return_value=[_generate_response(random_issuer, expected_jwk)]
    )

    mocked_issuer_jwt_vc_issuer_endpoint.start()

    trust_source = TrustSourceData.empty(random_issuer)
    trust_source = trust_handler.extract_and_update_trust_materials(random_issuer, trust_source)

    obtained_jwks = trust_source.keys
        
    mocked_issuer_jwt_vc_issuer_endpoint.stop()

    assert len(obtained_jwks) == 1, f"expected 1 jwk, obtained {len(obtained_jwks)}"
    assert expected_jwk == obtained_jwks[0]
