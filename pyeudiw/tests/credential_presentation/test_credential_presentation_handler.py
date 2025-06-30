import pytest

from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.settings import CONFIG
from pyeudiw.tests.trust import correct_config
from pyeudiw.trust.dynamic import CombinedTrustEvaluator


@pytest.fixture
def trust_evaluator():
    return CombinedTrustEvaluator.from_config(
        correct_config,
        DBEngine(CONFIG["storage"]),
        default_client_id="test-client"
    )


@pytest.fixture
def valid_config():
    return {
        "credential_presentation_handlers": {
            "max_submission_size": 2048,
            "formats": [
                {
                    "format": "mock_format",
                    "module": "pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers",
                    "class": "MockLdpVpHandler"
                }
            ]
        }
    }


def test_load_valid_config(trust_evaluator, valid_config):
    from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
    handler = load_credential_presentation_handlers(
        config=valid_config,
        trust_evaluator=trust_evaluator,
        sig_alg_supported=["ES256"]
    )

    from pyeudiw.credential_presentation.handler import CredentialPresentationHandlers
    assert isinstance(handler, CredentialPresentationHandlers)
    assert "mock_format" in handler.handlers
    assert handler.max_submission_size == 2048


def test_missing_credential_presentation_handlers_raises(trust_evaluator):
    from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
    with pytest.raises(ValueError) as exc:
        load_credential_presentation_handlers(
            config={},
            trust_evaluator=trust_evaluator
        )
    assert "Missing `credential_presentation_handlers`" in str(exc.value)


def test_missing_class_raises(trust_evaluator):
    invalid_config = {
        "credential_presentation_handlers": {
            "max_submission_size": 2048,
            "formats": [
                {
                    "format": "invalid",
                    "module": "pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers",
                    "class": "NonExistentHandler"
                }
            ]
        }
    }

    from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
    with pytest.raises(ImportError) as exc:
        load_credential_presentation_handlers(
            config=invalid_config,
            trust_evaluator=trust_evaluator
        )
    assert "Class 'NonExistentHandler' not found in module" in str(exc.value)


def test_missing_module_raises(trust_evaluator):
    invalid_config = {
        "credential_presentation_handlers": {
            "max_submission_size": 2048,
            "formats": [
                {
                    "format": "invalid",
                    "module": "not.a.real.module",
                    "class": "SomeHandler"
                }
            ]
        }
    }

    from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
    with pytest.raises(ImportError) as exc:
        load_credential_presentation_handlers(
            config=invalid_config,
            trust_evaluator=trust_evaluator
        )
    assert "Module 'not.a.real.module' not found" in str(exc.value)


def test_class_not_subclass_of_base_raises(trust_evaluator):
    invalid_config = {
        "credential_presentation_handlers": {
            "max_submission_size": 2048,
            "formats": [
                {
                    "format": "not_subclass",
                    "module": "pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers",
                    "class": "NotASubclass"
                }
            ]
        }
    }

    from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
    with pytest.raises(ImportError) as exc:
        load_credential_presentation_handlers(
            config=invalid_config,
            trust_evaluator=trust_evaluator
        )
    assert "Class 'NotASubclass' not found in module 'pyeudiw.tests.satosa.backends.openid4vp.mock_parser_handlers' for format 'not_subclass'." in str(exc.value)


def test_empty_formats_raises(trust_evaluator):
    invalid_config = {
        "credential_presentation_handlers": {
            "max_submission_size": 2048,
            "formats": []
        }
    }

    from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
    with pytest.raises(ValueError) as exc:
        load_credential_presentation_handlers(
            config=invalid_config,
            trust_evaluator=trust_evaluator
        )
    assert "must define at least one format" in str(exc.value)
