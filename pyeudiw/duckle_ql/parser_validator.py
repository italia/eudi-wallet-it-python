"""
Parser and validator for DCQL (Duckle) Verifiable Presentation requests.

This module provides ParserValidator to detect and validate VP tokens when
the backend is configured with config.dcql_query (DCQL flow).
"""

import logging
from typing import Any

from pyeudiw.duckle_ql.handler import DuckleHandler
from pyeudiw.exceptions import ValidationError
from pyeudiw.duckle_ql.utils import DUCKLE_QUERY_KEY
from pyeudiw.duckle_ql.exceptions import MissingHandler


class ParserValidator:
    """
    Validates Verifiable Presentation tokens for the DCQL (Duckle) flow.

    Use is_active_duckle_request() to check if the current request is a DCQL request
    (i.e. config.dcql_query is set). When active, parse() and validate()
    use the DuckleHandler to process the VP token.
    """

    def __init__(self, token: Any, handlers: dict, config: dict):
        self.token = token
        self.config = config
        self.handler = self._extract_handler(handlers)

    def parse(self) -> list[dict]:
        return [self.handler.parse(self.token)]

    def validate(self, verifier_id: str, verifier_nonce: str) -> None:
        """
        Validate the DCQL presentation data using the DuckleHandler.

        :raises MissingHandler: If the handler for the format is not found.
        :raises VPTokenDescriptorMapMismatch: If the number of VP tokens does not match the number of descriptors.
        :raises ParseError: If parsing fails.
        """
        try:
            self.handler.validate(self.token, verifier_id, verifier_nonce)
        except Exception as e:
            raise ValidationError(f"Error parsing token at position: {e}")

    def _extract_handler(self, handlers: dict):
        if self.config.get(DUCKLE_QUERY_KEY):
            for value in handlers.values():
                if isinstance(value, DuckleHandler):
                    return value
            raise MissingHandler("Handler not found for DCQL tokens!")

        logging.error("Handler not defined for current token!")
        return None

    def is_active_duckle_request(self) -> bool:
        """
        Return True if the backend is configured for DCQL (Duckle) flow
        (config.dcql_query present) and the token is a single object
        (DCQL VP format), not a list of encoded VPs (PE format).
        """
        if isinstance(self.token, list):
            return False
        return bool(self.config.get(DUCKLE_QUERY_KEY))
