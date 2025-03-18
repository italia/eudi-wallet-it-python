import re
from pydantic import ValidationError
import importlib
from typing import Any
import logging

from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser
from pyeudiw.openid4vp.presentation_submission.schemas import PresentationSubmissionSchema
from pyeudiw.openid4vp.presentation_submission.exceptions import (
    MissingHandler, 
    MalformedPath, 
    SubmissionValidationError, 
    VPTokenDescriptorMapMismatch,
    ParseError
)

logger = logging.getLogger(__name__)

class PresentationSubmissionHandler:
    def __init__(self, formats: list[dict], max_submission_size: int = 4096) -> None:
        """
        Initialize the PresentationSubmissionHandler handler with the submission data.

        :param submission: The presentation submission data.
        :type submission: dict[str, Any]
        :param config: Configuration dictionary.
        :type config: dict[str, Any], optional
        :param args: Additional arguments to be passed to handlers.
        :type args: Any
        :param kwargs: Additional keyword arguments to be passed to handlers.
        :type kwargs: Any

        :raises KeyError: If the 'format' key is missing in the submission.
        :raises ValueError: If the format is not supported or not defined in the configuration.
        :raises ImportError: If the module or class cannot be loaded.
        :raises ValidationError: If the submission data is invalid or exceeds size limits.
        """
        if not formats:
            raise ValueError("At least one format must be defined.")

        self.max_submission_size = max_submission_size
        self.handlers: dict[str, BaseVPParser] = {}

        for format_conf in formats:
            module_name = format_conf["module"]
            class_name = format_conf["class"]
            handler_name = format_conf["name"]
            module_config = format_conf.get("config", {})

            try:
                # Dynamically load the module and class
                module = importlib.import_module(module_name)
                cls = getattr(module, class_name)
                
                if not issubclass(cls, BaseVPParser):
                     raise TypeError(f"Class '{class_name}' must inherit from BaseVPParser.")
                
                self.handlers[handler_name] = cls(**module_config)
            except ModuleNotFoundError:
                raise ImportError(f"Module '{module_name}' not found for format '{format_conf['name']}'.")
            except AttributeError:
                raise ImportError(f"Class '{class_name}' not found in module '{module_name}' for format '{format_conf['name']}'.")
            except Exception as e:
                raise ImportError(f"Error loading class '{class_name}' from module '{module_name}': {e}")
        
    def _validate_submission(self, submission: dict[str, Any]) -> PresentationSubmissionSchema:
        """
        Validate the submission data using Pydantic and check its total size.

        :param submission: The presentation submission data.
        :type submission: dict[str, Any]

        :raises SubmissionValidationError: If the submission data is invalid or exceeds size limits.

        :return: Validated submission schema.
        :rtype: PresentationSubmissionSchema
        """
        # Check submission size
        submission_size = len(str(submission).encode("utf-8"))
        if submission_size > self.max_submission_size:
            raise SubmissionValidationError(
                f"Submission size exceeds maximum allowed limit of {self.max_submission_size} bytes."
            )

        try:
            return PresentationSubmissionSchema(**submission)
        except ValidationError as e:
            raise SubmissionValidationError(f"Submission validation failed: {e}")
    
    def _extract_position(self, path: str) -> tuple[str, str]:
        """
        Extract the position and path from the descriptor path.

        :param path: The descriptor path.
        :type path: str

        :raises MalformedPath: If the path is not in the correct format.

        :return: Tuple of position and path.
        :rtype: tuple[str, str]
        """
        pattern = r'\$\[(\d+)\]'
        match = re.search(pattern, path)
        if match:
            position = int(match.group(1))
            return position
        else:
            raise MalformedPath(f"Invalid path format: {path}")

    def parse(self, submission: dict[str, Any], vp_tokens: list[str]) -> list[dict]:
        """
        Parse the presentation submission data using the appropriate handler.

        :param submission: The presentation submission data.
        :type submission: dict[str, Any]

        :raises MissingHandler: If the handler for the format is not found.
        :raises VPTokenDescriptorMapMismatch: If the number of VP tokens does not match the number of descriptors.
        :raises ParseError: If parsing fails.

        :return: Parsed presentation submission data.
        :rtype: dict
        """
        validated_submission = self._validate_submission(submission)

        descriptor_map_len = len(validated_submission.descriptor_map)

        if len(vp_tokens) != descriptor_map_len:
            raise VPTokenDescriptorMapMismatch(
                f"Number of VP tokens ({len(vp_tokens)}) does not match the number of descriptors ({descriptor_map_len})."
            )
        
        parsed_tokens = [None] * descriptor_map_len
        
        for descriptor in validated_submission.descriptor_map:
            handler = self.handlers.get(descriptor.format)

            if not handler:
                raise MissingHandler(f"Handler for format '{descriptor.format}' not found.")
            
            position = self._extract_position(descriptor.path)

            try:
                parsed_tokens[position] = handler.parse(vp_tokens[position])
            except Exception as e:
                raise ParseError(f"Error parsing token at position {position}: {e}")

        return parsed_tokens