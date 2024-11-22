import pytest
from unittest.mock import patch, MagicMock
from pyeudiw.openid4vp.presentation_submission import PresentationSubmission


# Mock data for testing
mock_format_config = {
    "formats": [
        {"name": "ldp_vp", "module": "mock.module", "class": "MockLdpVpHandler"},
        {"name": "jwt_vp_json", "module": "mock.module", "class": "MockJwtVpJsonHandler"}
    ]
}

valid_submission = {
    "descriptor_map": [
        {"format": "ldp_vp", "id": "descriptor_1", "path": "$"},
        {"format": "jwt_vp_json", "id": "descriptor_2", "path": "$"}
    ]
}

def test_presentation_submission_initialization():
    """
    Test that the PresentationSubmission class initializes correctly,
    loads handlers for all valid formats, and handles missing configurations.
    """
    # Mock handler classes
    mock_ldp_vp_handler = MagicMock(name="MockLdpVpHandler")
    mock_jwt_vp_json_handler = MagicMock(name="MockJwtVpJsonHandler")

    # Mock import_module to return a fake module with our mock classes
    mock_module = MagicMock()
    setattr(mock_module, "MockLdpVpHandler", mock_ldp_vp_handler)
    setattr(mock_module, "MockJwtVpJsonHandler", mock_jwt_vp_json_handler)

    with patch("pyeudiw.openid4vp.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config), \
         patch("importlib.import_module", return_value=mock_module):
        
        # Initialize the class
        ps = PresentationSubmission(valid_submission)

        # Assert that handlers were created for all formats in descriptor_map
        assert len(ps.handlers) == len(valid_submission["descriptor_map"]), "Not all handlers were created."

        # Check that the handlers are instances of the mocked classes
        assert ps.handlers[0] is mock_ldp_vp_handler(), "Handler for 'ldp_vp' format is incorrect."
        assert ps.handlers[1] is mock_jwt_vp_json_handler(), "Handler for 'jwt_vp_json' format is incorrect."

def test_presentation_submission_invalid_format():
    """
    Test that the PresentationSubmission class handles unsupported formats gracefully.
    """
    invalid_submission = {
        "descriptor_map": [
            {"format": "unsupported_format", "id": "descriptor_3", "path": "$"}
        ]
    }

    with patch("pyeudiw.openid4vp.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config):
        # Expect a ValueError for unsupported format
        with pytest.raises(ValueError, match="Format 'unsupported_format' is not supported or not defined in the configuration."):
            PresentationSubmission(invalid_submission)

def test_presentation_submission_missing_format_key():
    """
    Test that the PresentationSubmission class raises KeyError
    when the 'format' key is missing in a descriptor.
    """
    missing_format_submission = {
        "descriptor_map": [
            {"id": "descriptor_4", "path": "$"}
        ]
    }

    with patch("pyeudiw.openid4vp.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config):
        # Expect a KeyError for missing 'format'
        with pytest.raises(KeyError, match="The 'format' key is missing in descriptor at index 0."):
            PresentationSubmission(missing_format_submission)
