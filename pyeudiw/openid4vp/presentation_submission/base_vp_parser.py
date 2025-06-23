from abc import ABC, abstractmethod
from typing import Any, Dict

from pyeudiw.trust.dynamic import CombinedTrustEvaluator

class BaseVPParser(ABC):
    """
    Standard interface for parsing Verifiable Presentations (VP).
    Each parser must implement these methods to ensure uniformity.
    """
    def __init__(self, trust_evaluator: CombinedTrustEvaluator, **kwargs):
        self.trust_evaluator = trust_evaluator

    @abstractmethod
    def parse(self, token: str) -> Dict[str, Any]:
        """Parses a Verifiable Presentation token."""
        pass

    @abstractmethod
    def validate(
        self, 
        token: str, 
        verifier_id: str, 
        verifier_nonce: str
    ) -> bool:
        """Validates the content of a Verifiable Presentation."""
        pass