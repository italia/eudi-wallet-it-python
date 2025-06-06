from satosa.context import Context

from pyeudiw.tools.session import get_session_id


def test_get_session_id():
    mock_context = Context()
    expected_session_id = "test-session-1234"
    mock_context.state = {"SESSION_ID": expected_session_id}

    assert get_session_id(mock_context) == expected_session_id
