import importlib
from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

METADATA_JWKS_CONFIG_KEY = "metadata_jwks"
JWT_CONFIG_KEY = "jwt"
CREDENTIAL_PRESENTATION_HANDLERS_CONFIG_KEY = "credential_presentation_handlers"
DUCKLE_PRESENTATION = "presentation"

class FormatConfig(BaseModel):
    """
    This class defines the configuration for a credential presentation format.

    Attributes:
        format (str): The name of the credential presentation format.
        module (str): The module that contains the handler class for the format.
        class_ (str): The name of the handler class (alias for 'class').
        config (dict): A dictionary of configuration parameters specific to the handler class.
    """
    format: str
    module: str
    class_: str = Field(..., alias="class")
    config: dict = {}


class CredentialPresentationHandlersConfig(BaseModel):
    """
    Configuration class for credential presentation handlers.

    This class defines the configuration for credential presentation handlers and validates that
    at least one format is provided. It includes parameters like max submission size, supported formats,
    the trust evaluator, and supported signature algorithms.

    Attributes:
        max_submission_size (Optional[int]): The maximum size (in bytes) for a presentation. Default is 4096.
        formats (List[FormatConfig]): A list of format configurations that specify the formats and handlers.
        trust_evaluator (CombinedTrustEvaluator): The trust evaluator used to evaluate the credential presentations.
        sig_alg_supported (list[str]): A list of supported signature algorithms.
    """
    max_submission_size: Optional[int] = None
    formats: List[FormatConfig]
    trust_evaluator: CombinedTrustEvaluator
    sig_alg_supported: list[str] = []

    class Config:
        arbitrary_types_allowed = True

    @model_validator(mode="before")
    def validate_formats(cls, values):
        """
        Validates that at least one format is defined in the configuration.

        Args:
            cls: The class type.
            values (dict): The configuration values to be validated.

        Raises:
            ValueError: If no formats are defined in the configuration.
        """
        formats = values.get("formats")
        if not formats:
            raise ValueError("credential_presentation_handlers must define at least one format.")
        return values


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

    duckle_handler = next((handler for handler in config_model.formats if handler.class_ == "DuckleHandler"), None)
    if duckle_handler:
        updated_config = {
            JWT_CONFIG_KEY: config.get(JWT_CONFIG_KEY, {}),
            METADATA_JWKS_CONFIG_KEY: config.get(METADATA_JWKS_CONFIG_KEY, []),
            DUCKLE_PRESENTATION: config.get("duckle", {}).get(DUCKLE_PRESENTATION, [])
        }
        duckle_handler.config = add_to_config(updated_config, duckle_handler.config)
    return CredentialPresentationHandlers(config_model)

def add_to_config(config: dict, handler_config: dict):
    """
    Dynamically adds elements from the config to the handler_config.
    It handles both dictionaries (using .update()) and lists (using .extend()).

    Parameters:
        config (dict): The configuration dictionary that contains the updates.
        handler_config (dict): The handler's current configuration to be updated.

    Returns:
        dict: The updated handler_config with new data from config.

    If the value in config is a dictionary, it updates the corresponding key in handler_config.
    If the value is a list, it extends the existing list in handler_config with the new items.
    If the value is of any other type, it directly adds or updates the key in handler_config.
    """
    for key, value in config.items():
        if isinstance(value, dict):
            # If the value is a dictionary, update the key with .update()
            if key not in handler_config:
                handler_config[key] = {}
            handler_config[key].update(value)
        elif isinstance(value, list):
            # If the value is a list, extend the key with .extend()
            if key not in handler_config:
                handler_config[key] = []
            handler_config[key].extend(value)
        else:
            # For any other data type, simply add or update the key in handler_config
            handler_config[key] = value
    return handler_config
