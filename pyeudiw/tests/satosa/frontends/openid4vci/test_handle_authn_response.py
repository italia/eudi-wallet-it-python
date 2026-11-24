from copy import deepcopy
from unittest.mock import Mock, patch

from satosa.internal import AuthenticationInformation, InternalData

from pyeudiw.tests.satosa.frontends.openid4vci.mock_openid4vci import (
    MOCK_BASE_URL,
    MOCK_INTERNAL_ATTRIBUTES,
    MOCK_NAME,
    MOCK_PYEUDIW_FRONTEND_CONFIG,
    get_mocked_openid4vpi_entity,
    get_mocked_satosa_context,
)


def _internal_resp() -> InternalData:
    return InternalData(
        auth_info=AuthenticationInformation("acr", "timestamp", "issuer"),
        attributes={"given_name": ["Mario"]},
    )


@patch(
    "pyeudiw.satosa.frontends.openid4vci.openid4vci.OpenId4VciDBEngineHandler"
)
def test_handle_authn_response_uses_vci_document_id(mock_engine_handler):
    from pyeudiw.satosa.frontends.openid4vci.openid4vci import OpenID4VCIFrontend

    mock_engine_handler.return_value.db_engine = Mock()
    frontend = OpenID4VCIFrontend(
        Mock(), MOCK_INTERNAL_ATTRIBUTES, MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_BASE_URL, MOCK_NAME
    )
    entity = get_mocked_openid4vpi_entity()
    entity["abandoned"] = False
    entity["finalized"] = False
    frontend.db_engine.get_by_id.return_value = entity
    context = get_mocked_satosa_context()
    context.state["openid4vci_document_id"] = entity["document_id"]

    response = frontend.handle_authn_response(context, _internal_resp())

    assert str(response.status).startswith("302")
    frontend.db_engine.get_by_id.assert_called_once_with(entity["document_id"])
    frontend.db_engine.get_pending_openid4vci_by_session_id.assert_not_called()
    frontend.db_engine.upsert_session_by_document_id.assert_called_once()
    args = frontend.db_engine.upsert_session_by_document_id.call_args.args
    assert args[0] == entity["document_id"]
    assert args[1]["finalized"] is True
    assert args[1]["auth_code"]


@patch(
    "pyeudiw.satosa.frontends.openid4vci.openid4vci.OpenId4VciDBEngineHandler"
)
def test_handle_authn_response_falls_back_to_pending_vci(mock_engine_handler):
    from pyeudiw.satosa.frontends.openid4vci.openid4vci import OpenID4VCIFrontend

    mock_engine_handler.return_value.db_engine = Mock()
    frontend = OpenID4VCIFrontend(
        Mock(), MOCK_INTERNAL_ATTRIBUTES, MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_BASE_URL, MOCK_NAME
    )
    entity = get_mocked_openid4vpi_entity()
    frontend.db_engine.get_pending_openid4vci_by_session_id.return_value = entity
    context = get_mocked_satosa_context()

    response = frontend.handle_authn_response(context, _internal_resp())

    assert str(response.status).startswith("302")
    frontend.db_engine.get_pending_openid4vci_by_session_id.assert_called_once_with(
        "sessionid"
    )
    frontend.db_engine.upsert_session_by_document_id.assert_called_once()


@patch(
    "pyeudiw.satosa.frontends.openid4vci.openid4vci.OpenId4VciDBEngineHandler"
)
def test_handle_authn_response_rejects_abandoned_vci(mock_engine_handler):
    from pyeudiw.satosa.frontends.openid4vci.openid4vci import OpenID4VCIFrontend

    mock_engine_handler.return_value.db_engine = Mock()
    frontend = OpenID4VCIFrontend(
        Mock(), MOCK_INTERNAL_ATTRIBUTES, MOCK_PYEUDIW_FRONTEND_CONFIG, MOCK_BASE_URL, MOCK_NAME
    )
    entity = deepcopy(get_mocked_openid4vpi_entity())
    entity["abandoned"] = True
    entity["finalized"] = True
    frontend.db_engine.get_pending_openid4vci_by_session_id.return_value = entity
    context = get_mocked_satosa_context()

    response = frontend.handle_authn_response(context, _internal_resp())

    assert response.status == "400"
    frontend.db_engine.upsert_session_by_document_id.assert_not_called()
