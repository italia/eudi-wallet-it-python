import re

import pytest
from satosa.response import Response

from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context
)
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER

JWS_HELPER_VERIFY_TARGET = "pyeudiw.jwt.jws_helper.JWSHelper.verify"

def assert_invalid_request_application_json(result: Response, error_desc: str):
    assert result.status == '400'
    assert result.message == f'{{"error": "invalid_request", "error_description": "{error_desc}"}}'

def do_test_missing_configurations_raises(handler, config, missing_fields):
    with pytest.raises(
            ValueError,
            match=re.escape(f"The following configuration fields must be provided and non-empty: {', '.join(missing_fields)}")
    ):
        handler(config, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)

def do_test_invalid_request_method(handler, context, method, assert_invalid_request = assert_invalid_request_application_json):
    context.request_method = method
    assert_invalid_request(
        handler.endpoint(context),
        "invalid request method"
    )

def do_test_invalid_content_type(handler, context, content_type, assert_invalid_request = assert_invalid_request_application_json):
    context.http_headers[HTTP_CONTENT_TYPE_HEADER] = content_type
    assert_invalid_request(
        handler.endpoint(context),
        "invalid content-type"
    )

def do_test_invalid_oauth_client_attestation(handler, headers, assert_invalid_request = assert_invalid_request_application_json):
    assert_invalid_request(
        handler.endpoint(get_mocked_satosa_context(headers=headers)),
        "Missing Wallet Attestation JWT header"
    )

