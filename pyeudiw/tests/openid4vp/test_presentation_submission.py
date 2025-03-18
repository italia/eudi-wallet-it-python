from pyeudiw.openid4vp.presentation_submission import PresentationSubmissionHandler
from pyeudiw.tests.openid4vp.mock_parser_handlers import MockLdpVpHandler, MockJwtVpJsonHandler
from pyeudiw.openid4vp.presentation_submission.exceptions import SubmissionValidationError

# Mock data for testing
mock_format_config = {
    "formats": [
        {
            "name": "ldp_vp", 
            "module": "pyeudiw.tests.openid4vp.test_presentation_submission", 
            "class": "MockLdpVpHandler"
        },
        {
            "name": "jwt_vp_json", 
            "module": "pyeudiw.tests.openid4vp.test_presentation_submission", 
            "class": "MockJwtVpJsonHandler"
        }
    ],
    "max_submission_size": 10 * 1024  # 10 KB
}

valid_submission = {
    "id": "submission_id",
    "definition_id": "definition_id",
    "descriptor_map": [
        {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
        {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"}
    ]
}


def test_handler_initialization():
    ps = PresentationSubmissionHandler(**mock_format_config)

    assert len(ps.handlers) == len(valid_submission["descriptor_map"]), "Not all handlers were created."

    assert isinstance(ps.handlers["ldp_vp"], MockLdpVpHandler), "Handler for 'ldp_vp' format is incorrect."
    assert isinstance(ps.handlers["jwt_vp_json"], MockJwtVpJsonHandler), "Handler for 'jwt_vp_json' format is incorrect."

def test_handler_correct_parsing():
    ps = PresentationSubmissionHandler(**mock_format_config)

    parsed_tokens = ps.parse(valid_submission, ["vp_token_1", "vp_token_2"])

    assert len(parsed_tokens) == len(valid_submission["descriptor_map"]), "Not all tokens were parsed."
    assert parsed_tokens[0] == {"parsed": "vp_token_1"}, "Token 1 was not parsed correctly."
    assert parsed_tokens[1] == {"parsed": "vp_token_2"}, "Token 2 was not parsed correctly."

def test_handler_missing_handler():
    ps = PresentationSubmissionHandler(**mock_format_config)

    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"},
            {"id": "descriptor_3", "format": "non_existent_format", "path": "$[2]"}
        ]
    }

    try:
        ps.parse(invalid_submission, ["vp_token_1", "vp_token_2", "vp_token_3"])
    except Exception as e:
        assert str(e) == "Handler for format 'non_existent_format' not found.", "Incorrect exception message."

def test_handler_invalid_path():
    ps = PresentationSubmissionHandler(**mock_format_config)

    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"},
            {"id": "descriptor_3", "format": "ldp_vp", "path": "invalid_path"}
        ]
    }

    try:
        ps.parse(invalid_submission, ["vp_token_1", "vp_token_2", "vp_token_3"])
    except Exception as e:
        assert str(e) == "Invalid path format: invalid_path", "Incorrect exception message."

def test_handler_mismatched_tokens():
    ps = PresentationSubmissionHandler(**mock_format_config)

    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"}
        ]
    }

    try:
        ps.parse(invalid_submission, ["vp_token_1"])
    except Exception as e:
        assert str(e) == "Number of VP tokens (1) does not match the number of descriptors (2).", "Incorrect exception message."

def test_handler_invalid_submission():
    ps = PresentationSubmissionHandler(**mock_format_config)

    invalid_submission = {
        "fail": "submission"
    }

    try:
        ps.parse(invalid_submission, ["vp_token_1", "vp_token_2"])
    except SubmissionValidationError as e:
        pass
    except Exception as e:
        assert False, f"Incorrect exception type: {type(e)}"
        