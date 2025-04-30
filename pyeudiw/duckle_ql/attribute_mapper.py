from typing import Dict, Any, List


def extract_claims(data: Dict[str, Any], paths: List[Dict[str, List[str]]]) -> Dict[str, Any]:
    """
    Extracts values from a dictionary (nested or flat) based on the provided paths.

    :param data: The input dictionary (can be nested or flat).
    :param paths: A list of dictionaries, each containing a "path" key with a list of key sequences to extract claims from.
    :param raise_missing: If True, raises an exception when one or more claims are missing (default is True).
    :return: A dictionary with the extracted values, preserving the nested structure if applicable.
    :raises ValueError: If any claim is missing and raise_missing is set to True.
    """

    def set_nested(d: dict, path: List[str], value: Any) -> None:
        """Sets a value in a nested dictionary structure according to the given path."""
        for key in path[:-1]:
            d = d.setdefault(key, {})
        d[path[-1]] = value

    result = {}
    missing = []

    for path_obj in paths:
        path = path_obj.get("path")
        if not path:
            continue

        if isinstance(path, list) and all(isinstance(p, str) for p in path):
            current = data
            try:
                for key in path:
                    current = current[key]
                set_nested(result, path, current)
            except (KeyError, TypeError):
                missing.append(".".join(path))
        else:
            # fallback for flat single-key paths (e.g. path=["given_name"])
            try:
                value = data[path[0]]
                result[path[0]] = value
            except (KeyError, TypeError, IndexError):
                missing.append(path[0])

    if missing:
        raise ValueError(f"Missing claims: {', '.join(missing)}")

    return result


def flatten_namespace(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flattens a nested dictionary by removing the top-level namespaces.

    :param data: A nested dictionary where each top-level key corresponds to a namespace.
    :return: A flattened dictionary containing all keys/values merged from all namespaces.
    """
    result = {}
    for namespace_dict in data.values():
        if isinstance(namespace_dict, dict):
            result.update(namespace_dict)
    return result