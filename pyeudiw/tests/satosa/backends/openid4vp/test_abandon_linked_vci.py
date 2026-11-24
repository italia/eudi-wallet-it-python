from unittest.mock import Mock

from satosa.context import Context

from pyeudiw.satosa.backends.openid4vp.endpoints.response_endpoint import ResponseHandler
from pyeudiw.satosa.backends.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.satosa.backends.openid4vp.schemas.response import ErrorResponsePayload


def test_error_response_abandons_linked_vci():
    handler = object.__new__(ResponseHandler)
    handler.db_engine = Mock()
    handler.response_code_helper = Mock()
    handler.response_code_helper.create_code.return_value = "rc"
    handler.registered_get_response_endpoint = "https://example.org/get-response"
    request_session = {
        "document_id": "vp-doc",
        "nonce": "nonce",
        "session_id": "browser-session",
        "remote_flow_typ": RemoteFlowType.SAME_DEVICE.value,
        "vci_document_id": "vci-doc",
    }
    handler._retrieve_session_from_state = Mock(return_value=request_session)

    response = handler._handle_error_response(
        Context(),
        ErrorResponsePayload(error="access_denied", state="vp-state"),
    )

    assert response.status == "200"
    handler.db_engine.abandon_linked_openid4vci.assert_called_once_with(request_session)


def test_get_response_sets_openid4vci_document_id_on_success():
    from pyeudiw.satosa.backends.openid4vp.endpoints.get_response_endpoint import (
        GetResponseHandler,
    )

    handler = object.__new__(GetResponseHandler)
    handler._auth_callback = Mock(return_value="ok")
    context = Context()
    context.state = {"SESSION_ID": "browser-session"}
    finalized = {
        "internal_response": {
            "attributes": {"given_name": ["Mario"]},
            "auth_info": {
                "issuer": "issuer",
                "auth_class_ref": "acr",
                "timestamp": "0",
            },
        },
        "vci_document_id": "vci-doc",
    }

    assert handler._get_response_auth_callback(context, finalized) == "ok"
    assert context.state["openid4vci_document_id"] == "vci-doc"
    handler._auth_callback.assert_called_once()
