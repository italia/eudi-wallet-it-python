import base64
import logging
from typing import Any

from pyeudiw.duckle_ql.handler import DuckleHandler
from pyeudiw.exceptions import ValidationError
from pyeudiw.presentation_definition.utils import DUCKLE_PRESENTATION
from pyeudiw.satosa.backends.openid4vp import MissingHandler


class ParserValidator:

    def __init__(self, token: Any, handlers: dict, config: dict):
        self.token = token
        self.config = config
        self.handler = self._extract_handler(handlers)

    def parse(self) -> list[dict]:
        return [self.handler.parse(self.token)]

    def validate(
            self,
            verifier_id: str,
            verifier_nonce: str
    ) -> None:
        """
        Validate the presentation definition data using the appropriate handler .

        :raises MissingHandler: If the handler for the format is not found.
        :raises VPTokenDescriptorMapMismatch: If the number of VP tokens does not match the number of descriptors.
        :raises ParseError: If parsing fails.
        """
        try:
            self.handler.validate(self.token, verifier_id, verifier_nonce)
        except Exception as e:
            raise ValidationError(f"Error parsing token at position: {e}")

    def _extract_handler(self, handlers: dict):
        queries_to_handlers = [
            (DUCKLE_PRESENTATION, DuckleHandler),
        ]

        for pres, handler_cls, in queries_to_handlers:
            if self.config.get(pres):
                for value in handlers.values():
                    if isinstance(value, handler_cls):
                        return value
                raise MissingHandler(f"Handler not found for {pres} tokens!")

        logging.error("Handler not defined for current token!")
        return None

    def is_active_presentation_definition(self) -> bool:
        if isinstance(self.token, list):
            return False
        return self.config.get(DUCKLE_PRESENTATION)

def _is_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3

def _decode_base64url(data: str) -> bytes:
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data)
