import pytest

from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
from pyeudiw.satosa.backends.openid4vp.presentation_submission import PresentationSubmissionHandler
from pyeudiw.satosa.backends.openid4vp.presentation_submission.exceptions import SubmissionValidationError
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers import MockLdpVpHandler, MockJwtVpJsonHandler, \
    MockFailingParser
from pyeudiw.tests.settings import CONFIG
from pyeudiw.tests.trust import correct_config
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

# Mock data for testing
mock_format_config = {
    "formats": [
        {
            "format": "ldp_vp",
            "module": "pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers",
            "class": "MockLdpVpHandler"
        },
        {
            "format": "jwt_vp_json",
            "module": "pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers",
            "class": "MockJwtVpJsonHandler"
        },
        {
            "format": "fail_parser",
            "module": "pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers",
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

@pytest.fixture
def ps():
    handler_config = load_credential_presentation_handlers(
        {"credential_presentation_handlers": mock_format_config},
        trust_evaluator=trust_ev,
        sig_alg_supported=["ES256", "ES384", "ES512"]
    )
    return PresentationSubmissionHandler(config=handler_config)

def test_handler_initialization(ps):
    assert len(ps.handlers) == 3
    assert isinstance(ps.handlers["ldp_vp"], MockLdpVpHandler)
    assert isinstance(ps.handlers["jwt_vp_json"], MockJwtVpJsonHandler)
    assert isinstance(ps.handlers["fail_parser"], MockFailingParser)

def test_handler_correct_parsing(ps):
    parsed_tokens = ps.parse(valid_submission, ["vp_token_1", "vp_token_2"])
    assert len(parsed_tokens) == 2
    assert parsed_tokens[0] == {"parsed": "vp_token_1"}
    assert parsed_tokens[1] == {"parsed": "vp_token_2"}

def test_handler_missing_handler(ps):
    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"},
            {"id": "descriptor_3", "format": "non_existent_format", "path": "$[2]"}
        ]
    }
    with pytest.raises(Exception) as exc_info:
        ps.validate(invalid_submission, ["vp_token_1", "vp_token_2", "vp_token_3"], "verifier_id", "verifier_nonce")
    assert "Handler for format 'non_existent_format' not found." in str(exc_info.value)

def test_handler_invalid_path(ps):
    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"},
            {"id": "descriptor_3", "format": "ldp_vp", "path": "invalid_path"}
        ]
    }
    with pytest.raises(Exception) as exc_info:
        ps.parse(invalid_submission, ["vp_token_1", "vp_token_2", "vp_token_3"])
    assert "Invalid path format: invalid_path" in str(exc_info.value)

def test_handler_mismatched_tokens(ps):
    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "ldp_vp", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"}
        ]
    }
    with pytest.raises(Exception) as exc_info:
        ps.validate(invalid_submission, ["vp_token_1"], "verifier_id", "verifier_nonce")
    assert "Number of VP tokens (1) does not match the number of descriptors (2)." in str(exc_info.value)

def test_handler_invalid_submission(ps):
    invalid_submission = {"fail": "submission"}
    with pytest.raises(SubmissionValidationError):
        ps.validate(invalid_submission, ["vp_token_1", "vp_token_2"], "verifier_id", "verifier_nonce")

def test_handler_parser_failure(ps):
    invalid_submission = {
        "id": "submission_id",
        "definition_id": "definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "format": "fail_parser", "path": "$[0]"},
            {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$[1]"}
        ]
    }
    with pytest.raises(Exception) as exc_info:
        ps.parse(invalid_submission, ["vp_token_1", "vp_token_2"])
    assert "Error parsing token at position 0: This parser is meant to fail." in str(exc_info.value)