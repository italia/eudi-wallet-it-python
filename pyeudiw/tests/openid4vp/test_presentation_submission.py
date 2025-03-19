from pyeudiw.openid4vp.presentation_submission import PresentationSubmissionHandler
from pyeudiw.tests.openid4vp.mock_parser_handlers import MockLdpVpHandler, MockJwtVpJsonHandler, MockFailingParser
from pyeudiw.openid4vp.presentation_submission.exceptions import SubmissionValidationError
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.settings import CONFIG
from pyeudiw.tests.trust import correct_config

# Mock data for testing
mock_format_config = {
    "formats": [
        {
            "format": "ldp_vp", 
            "module": "pyeudiw.tests.openid4vp.mock_parser_handlers", 
            "class": "MockLdpVpHandler"
        },
        {
            "format": "jwt_vp_json", 
            "module": "pyeudiw.tests.openid4vp.mock_parser_handlers", 
            "class": "MockJwtVpJsonHandler"
        },
        {
            "format": "fail_parser",
            "module": "pyeudiw.tests.openid4vp.mock_parser_handlers", 
            "class": "MockFailingParser"
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

trust_ev = CombinedTrustEvaluator.from_config(
    correct_config,
    DBEngine(CONFIG["storage"]),
    default_client_id="default-client-id",
)

def test_handler_initialization():

    ps = PresentationSubmissionHandler(trust_evaluator=trust_ev, config=mock_format_config)

    assert len(ps.handlers) == 3, "Not all handlers were created."

    assert isinstance(ps.handlers["ldp_vp"], MockLdpVpHandler), "Handler for 'ldp_vp' format is incorrect."
    assert isinstance(ps.handlers["jwt_vp_json"], MockJwtVpJsonHandler), "Handler for 'jwt_vp_json' format is incorrect."
    assert isinstance(ps.handlers["fail_parser"], MockFailingParser), "Handler for 'fail_parser' format is incorrect."

def test_handler_correct_parsing():
    ps = PresentationSubmissionHandler(trust_evaluator=trust_ev, config=mock_format_config)

    parsed_tokens = ps.parse(valid_submission, ["vp_token_1", "vp_token_2"])

    assert len(parsed_tokens) == len(valid_submission["descriptor_map"]), "Not all tokens were parsed."
    assert parsed_tokens[0] == {"parsed": "vp_token_1"}, "Token 1 was not parsed correctly."
    assert parsed_tokens[1] == {"parsed": "vp_token_2"}, "Token 2 was not parsed correctly."

def test_handler_missing_handler():
    ps = PresentationSubmissionHandler(trust_evaluator=trust_ev, config=mock_format_config)

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
        ps.validate(invalid_submission, ["vp_token_1", "vp_token_2", "vp_token_3"], "verifier_id", "verifier_nonce")
    except Exception as e:
        assert str(e) == "Handler for format 'non_existent_format' not found.", "Incorrect exception message."

def test_handler_invalid_path():
    ps = PresentationSubmissionHandler(trust_evaluator=trust_ev, config=mock_format_config)

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
    ps = PresentationSubmissionHandler(trust_evaluator=trust_ev, config=mock_format_config)

    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"}
        ]
    }

    try:
        ps.validate(invalid_submission, ["vp_token_1"], "verifier_id", "verifier_nonce")
    except Exception as e:
        assert str(e) == "Number of VP tokens (1) does not match the number of descriptors (2).", "Incorrect exception message."

def test_handler_invalid_submission():
    ps = PresentationSubmissionHandler(trust_evaluator=trust_ev, config=mock_format_config)

    invalid_submission = {
        "fail": "submission"
    }

    try:
        ps.validate(invalid_submission, ["vp_token_1", "vp_token_2"], "verifier_id", "verifier_nonce")
    except SubmissionValidationError as e:
        pass
    except Exception as e:
        assert False, f"Incorrect exception type: {type(e)}"
        
def test_handler_parser_failure():
    ps = PresentationSubmissionHandler(trust_evaluator=trust_ev, config=mock_format_config)

    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "fail_parser", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"}
        ]
    }

    try:
        ps.parse(invalid_submission, ["vp_token_1", "vp_token_2"])
    except Exception as e:
        assert str(e) == "Error parsing token at position 0: This parser is meant to fail."