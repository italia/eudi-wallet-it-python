import logging
from typing import Any

logger = logging.getLogger(__name__)

def _apply_operator(resolved_value: Any, operator: str, value: Any) -> bool:
    """
    Applies the operator to the resolved value and the expected value.

    Args:
        resolved_value (Any): The value resolved from the path in the example.
        operator (str): The operator to apply (e.g., "equals", "greater_than").
        value (Any): The expected value to compare against.

    Returns:
        bool: True if the operator check passes, False otherwise.
    """
    if operator == "equals":
        return resolved_value == value
    elif operator == "greater_than":
        return resolved_value > value
    elif operator == "less_than":
        return resolved_value < value
    else:
        logger.warning(f"Unsupported operator: {operator}")
        return False

def _evaluate_criterion(example: dict, criterion: dict) -> bool:
    """
    Evaluates whether a single criterion is satisfied by the given example.

    Args:
        example (dict): The credential example to check against.
        criterion (dict): The criterion definition.

    Returns:
        bool: True if satisfied, False otherwise.
    """
    path = criterion.get('path')
    operator = criterion.get('operator')
    expected = criterion.get('value')

    actual = _resolve_path(example, path)

    if actual is None:
        return False

    return _apply_operator(actual, operator, expected)

def _resolve_path(data: Any, path: str) -> Any:
    """
    Resolves a dotted path like 'credentialSubject.given_name' on nested dictionaries and lists.

    This function supports traversing through nested dictionaries and also handles lists
    by recursively resolving the remaining path on each list item and returning the first
    non-null result.

    Args:
        data (Any): The input data, usually a dictionary representing a credential or VC.
        path (str): The dotted path string to resolve (e.g., "credentialSubject.given_name").

    Returns:
        Any: The resolved value, or None if the path cannot be resolved.
    """
    try:
        parts = path.split(".")
        for part in parts:
            if isinstance(data, dict):
                # Navigate to the next level using the current key
                data = data.get(part)
            elif isinstance(data, list):
                # If we hit a list, try to resolve the remaining path in each item
                remaining_path = ".".join(parts[parts.index(part):])
                resolved = [_resolve_path(item, remaining_path) for item in data]
                # Return the first non-null value
                data = next((d for d in resolved if d is not None), None)
                break
            else:
                # If the current data is neither a dict nor a list, we can't resolve further
                return None

            if data is None:
                return None
        return data
    except Exception as e:
        logger.error(f"Error during retrieve dclq path: {e}")
        return None

class Criteria:
    def __init__(self, criteria_definition: list[dict]):
        self.criteria_definition = criteria_definition

    def validate(self, vp_token: dict) -> bool:
        """
        Validates that every criterion is satisfied by at least one credentialQuery in the VP token.

        Args:
            vp_token (dict): The VP token containing the credentialQuery list.

        Returns:
            bool: True if all criteria are satisfied by any credentialQuery.
        """
        if not isinstance(vp_token, dict):
            logger.warning("VP token is not a dictionary")
            return False

        query = vp_token.get('query', {})
        credential_queries = query.get('credentialQuery', [])

        if not credential_queries:
            logger.warning("No credentialQuery found in VP token")
            return False

        for criterion in self.criteria_definition:
            matched = any(
                _evaluate_criterion(cq.get('example', {}), criterion)
                for cq in credential_queries
            )
            if not matched:
                logger.info(f"Criterion not satisfied: {criterion}")
                return False

        return True


