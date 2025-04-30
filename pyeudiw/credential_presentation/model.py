from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

from pyeudiw.trust.dynamic import CombinedTrustEvaluator


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
