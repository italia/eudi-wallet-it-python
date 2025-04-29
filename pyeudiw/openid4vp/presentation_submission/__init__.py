import logging
import re
from typing import Any

from pydantic import ValidationError

from pyeudiw.credential_presentation.handler import CredentialPresentationHandlers
from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser
from pyeudiw.openid4vp.presentation_submission.exceptions import (
    MissingHandler,
    MalformedPath,
    SubmissionValidationError,
    VPTokenDescriptorMapMismatch,
    ParseError,
    ValidationError
)
from pyeudiw.openid4vp.presentation_submission.schemas import PresentationSubmissionSchema

logger = logging.getLogger(__name__)

class PresentationSubmissionHandler:
    def __init__(
            self,
            config: CredentialPresentationHandlers,
        ) -> None:
        """
        Initialize the PresentationSubmissionHandler handler with the submission data.
        :param config: Configuration object.
        """
        self.max_submission_size = config.max_submission_size or 4096
        self.handlers = config.handlers
        self.trust_evaluator = config.trust_evaluator

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
    
    def _extract_position(self, path: str) -> int:
        """
        Extract the position and path from the descriptor path.

        :param path: The descriptor path.
        :type path: str

        :raises MalformedPath: If the path is not in the correct format.

        :return: Tuple of position and path.
        :rtype: tuple[str, str]
        """
        pattern = r"\$[a-z_\-\.]*\[(\d+)\]"
        match = re.match(pattern, path, re.I)
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
        descriptor_map_len = len(submission["descriptor_map"])

        parsed_tokens = [None] * descriptor_map_len
        
        for descriptor in submission["descriptor_map"]:
            handler = self.handlers.get(descriptor['format'])            
            position = self._extract_position(descriptor['path'])

            try:
                parsed_tokens[position] = handler.parse(vp_tokens[position])
            except Exception as e:
                raise ParseError(f"Error parsing token at position {position}: {e}")

        return parsed_tokens
    
    def validate(
        self, 
        submission: dict[str, Any], 
        vp_tokens: list[str],
        verifier_id: str, 
        verifier_nonce: str
    ) -> None:
        """
        Validate the presentation submission data using the appropriate handler.

        :param submission: The presentation submission data.
        :type submission: dict[str, Any]

        :raises MissingHandler: If the handler for the format is not found.
        :raises VPTokenDescriptorMapMismatch: If the number of VP tokens does not match the number of descriptors.
        :raises ParseError: If parsing fails.
        """
        try:
            validated_submission = self._validate_submission(submission)
        except Exception as e:
            raise SubmissionValidationError(f"Submission validation failed: {e}")

        descriptor_map_len = len(validated_submission.descriptor_map)

        if len(vp_tokens) != descriptor_map_len:
            raise VPTokenDescriptorMapMismatch(
                f"Number of VP tokens ({len(vp_tokens)}) does not match the number of descriptors ({descriptor_map_len})."
            )
        
        for descriptor in validated_submission.descriptor_map:
            handler = self.handlers.get(descriptor.format)

            if not handler:
                raise MissingHandler(f"Handler for format '{descriptor.format}' not found.")
            
            position = self._extract_position(descriptor.path)

            try:
                handler.validate(vp_tokens[position], verifier_id, verifier_nonce)
            except Exception as e:
                raise ValidationError(f"Error parsing token at position {position}: {e}")