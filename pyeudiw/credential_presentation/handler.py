import importlib
from typing import Optional, List

from pyeudiw.credential_presentation.model import CredentialPresentationHandlersConfig
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

METADATA_JWKS_CONFIG_KEY = "metadata_jwks"
CREDENTIAL_PRESENTATION_HANDLERS_CONFIG_KEY = "credential_presentation_handlers"

class CredentialPresentationHandlers:
    """
    This class manages credential presentation handlers based on the given configuration.

    It loads and initializes the handlers for the specified formats and ensures they are
    correctly configured with the appropriate trust evaluator and signature algorithms.

    Attributes:
        max_submission_size (int): The maximum size (in bytes) for a presentation.
        handlers (dict[str, BaseVPParser]): A dictionary where the keys are format names and values are the handler instances.
        trust_evaluator (CombinedTrustEvaluator): The trust evaluator used for assessing the presentations.
    """
    def __init__(self, config: CredentialPresentationHandlersConfig) -> None:
        """
        Initializes the credential presentation handlers based on the provided configuration.

        Args:
            config (CredentialPresentationHandlersConfig): The configuration to initialize the handlers.

        Raises:
            ImportError: If there is an issue with loading the required handler modules or classes.
        """
        self.max_submission_size = config.max_submission_size or 4096
        from pyeudiw.openid4vp.presentation_submission import BaseVPParser
        self.handlers: dict[str, BaseVPParser] = {}
        self.trust_evaluator = config.trust_evaluator

        for format_conf in config.formats:
            module_name = format_conf.module
            class_name = format_conf.class_
            format_name = format_conf.format
            module_config = format_conf.config

            try:
                module = importlib.import_module(module_name)
                cls = getattr(module, class_name)

                if not issubclass(cls, BaseVPParser):
                    raise TypeError(f"Class '{class_name}' must inherit from BaseVPParser.")

                self.handlers[format_name] = cls(
                    trust_evaluator=config.trust_evaluator,
                    **module_config,
                    sig_alg_supported=config.sig_alg_supported
                )
            except ModuleNotFoundError:
                raise ImportError(f"Module '{module_name}' not found for format '{format_name}'.")
            except AttributeError:
                raise ImportError(f"Class '{class_name}' not found in module '{module_name}' for format '{format_name}'.")
            except Exception as e:
                raise ImportError(f"Error loading class '{class_name}' from module '{module_name}': {e}")


def load_credential_presentation_handlers(
        config: dict,
        trust_evaluator: CombinedTrustEvaluator,
        sig_alg_supported: Optional[List[str]] = None
) -> CredentialPresentationHandlers:
    """
    Loads and validates the configuration for credential presentation handlers.

    This function takes the configuration, validates the necessary parameters, and returns an instance of
    `CredentialPresentationHandlers` initialized with the provided configuration.

    Args:
        config (dict): The configuration dictionary for the credential presentation handlers.
        trust_evaluator (CombinedTrustEvaluator): An instance of `CombinedTrustEvaluator` to evaluate trust.
        sig_alg_supported (Optional[List[str]]): A list of supported signature algorithms. Defaults to an empty list.

    Returns:
        CredentialPresentationHandlers: An instance of `CredentialPresentationHandlers` with the provided configuration.

    Raises:
        ValueError: If the `credential_presentation_handlers` configuration is missing.
        ImportError: If there is an issue with loading the required handler modules or classes.
    """
    raw_config = config.get(CREDENTIAL_PRESENTATION_HANDLERS_CONFIG_KEY, {})
    if not raw_config:
        raise ValueError("Missing `credential_presentation_handlers`!")

    if sig_alg_supported is None:
        sig_alg_supported = []

    config_model = CredentialPresentationHandlersConfig(
        **raw_config,
        trust_evaluator=trust_evaluator,
        sig_alg_supported=sig_alg_supported
    )
    return CredentialPresentationHandlers(config_model)