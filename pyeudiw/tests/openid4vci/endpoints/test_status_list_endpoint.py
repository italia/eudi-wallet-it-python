from copy import deepcopy
from unittest.mock import patch

import jwt
import pytest
from satosa.context import Context

from pyeudiw.openid4vci.endpoints.status_list_endpoint import StatusListHandler
from pyeudiw.tests.openid4vci.endpoints.endpoints_test import (
    do_test_invalid_request_method,
    do_test_missing_configurations_raises,
    do_test_invalid_content_type, assert_invalid_request_application_json
)
from pyeudiw.tests.openid4vci.mock_openid4vci import (
    INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON,
    INVALID_METHOD_FOR_GET_REQ,
    MOCK_STATUS_LIST_CONFIG,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_BASE_URL,
    get_mocked_satosa_context,
    mock_deserialized_overridable,
    REMOVE
)
from pyeudiw.tools.content_type import (
    APPLICATION_JSON,
    ACCEPT_HEADER,
    STATUS_LIST_JWT, STATUS_LIST_CWT
)

_BASE_PATH = "pyeudiw.openid4vci.endpoints.status_list_endpoint"

@pytest.fixture
def status_list_handler() -> StatusListHandler:
    with (patch(f"{_BASE_PATH}.UserCredentialEngine") as user_cred_eng_class,
          patch("pyeudiw.storage.user_credential_db_engine.CredentialStorage") as credential_storage_mock):
        user_cred_eng_class.db_user_storage_engine = credential_storage_mock.return_value
        handler = StatusListHandler(MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_INTERNAL_ATTRIBUTES, MOCK_BASE_URL, MOCK_NAME)
        return handler

@pytest.fixture()
def context() -> Context:
    return get_mocked_satosa_context(method="GET", content_type=APPLICATION_JSON)

@pytest.mark.parametrize("method", INVALID_METHOD_FOR_GET_REQ)
def test_invalid_request_method(status_list_handler, context, method):
    do_test_invalid_request_method(status_list_handler, context, method)

@pytest.mark.parametrize("content_type", INVALID_CONTENT_TYPES_NOT_APPLICATION_JSON)
def test_invalid_content_type(status_list_handler, context, content_type):
    do_test_invalid_content_type(status_list_handler, context, content_type)

@pytest.mark.parametrize("config, missing_fields", [
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, {"credential_configurations": REMOVE}), ["credential_configurations"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, {"credential_configurations.status_list": REMOVE}), ["credential_configurations.status_list"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, {"credential_configurations.status_list.exp": REMOVE}), ["credential_configurations.status_list.exp"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, {"credential_configurations.status_list.path": REMOVE}), ["credential_configurations.status_list.path"]),
    (mock_deserialized_overridable(MOCK_PYEUDIW_FRONTEND_CONFIG, {"credential_configurations.status_list.ttl": REMOVE}), ["credential_configurations.status_list.ttl"]),
])
def test_missing_configurations_raises(config, missing_fields):
    do_test_missing_configurations_raises(StatusListHandler, config, missing_fields)

@pytest.mark.parametrize("accept_header, error_desc", [
    (None, "Missing accept header"),
    ("", "Missing accept header"),
    (" ", "Invalid accept header"),
    ("accept-random-value", "Invalid accept header"),
])
def test_invalid_accept_header(status_list_handler, context, accept_header, error_desc):
    ctx = deepcopy(context)
    if accept_header:
        ctx.http_headers[ACCEPT_HEADER] = accept_header
    assert_invalid_request_application_json(
        status_list_handler.endpoint(ctx), error_desc)

status_array = [
    {"incremental_id": 1, "revoked": False},
    {"incremental_id": 2, "revoked": True},
    {"incremental_id": 3, "revoked": False},
    {"incremental_id": 4, "revoked": True},
    {"incremental_id": 5, "revoked": False},
]

def test_should_return_status_list_jwt_credentials(status_list_handler, context):
    should_return_status_list(status_list_handler, context, STATUS_LIST_JWT, status_array,
                              {'bits': 1, 'lst': '01010'})

def test_should_return_status_list_jwt_without_credentials(status_list_handler, context):
    should_return_status_list(status_list_handler, context, STATUS_LIST_JWT, [],
                              {'bits': 1, 'lst': ''})

def should_return_status_list(status_list_handler, context: Context, accept_header: str, status_list: list[dict],
                              expected_status_list: dict):
    status_list_handler._db_credential_engine.get_all_sorted_by_incremental_id.return_value = status_list
    ctx = deepcopy(context)
    ctx.http_headers[ACCEPT_HEADER] = accept_header
    result = status_list_handler.endpoint(ctx)
    assert result.status == '200 OK'
    if accept_header == STATUS_LIST_JWT:
        credential = jwt.decode(result.message, options={"verify_signature": False})
    elif  accept_header == STATUS_LIST_CWT:
        credential = {}
    else:
        pytest.fail(f"Unexpected accept header value: {accept_header}")
    assert credential is not None
    assert credential["sub"] == f'{MOCK_BASE_URL}/{MOCK_NAME}{MOCK_STATUS_LIST_CONFIG["path"]}/1'
    assert credential["ttl"] == MOCK_STATUS_LIST_CONFIG["ttl"]
    assert credential["exp"] - credential["iat"] == MOCK_STATUS_LIST_CONFIG["exp"]
    assert credential["status_list"] == expected_status_list
