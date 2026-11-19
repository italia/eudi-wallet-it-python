from typing import Any, Dict, List, Optional, Sequence


def _claim_id(claim: Any, index: int) -> str:
    claim_id = getattr(claim, "id", None)
    if isinstance(claim_id, str) and claim_id:
        return claim_id
    if isinstance(claim, dict):
        claim_id = claim.get("id")
        if isinstance(claim_id, str) and claim_id:
            return claim_id
        path = claim.get("path") or []
    else:
        path = getattr(claim, "path", None) or []
    if isinstance(path, list) and path:
        return ".".join(str(part) for part in path)
    return str(index)


def _claim_path(claim: Any) -> List[str]:
    if isinstance(claim, dict):
        path = claim.get("path") or []
    else:
        path = getattr(claim, "path", None) or []
    return list(path) if isinstance(path, list) else []


def _missing_paths(data: Dict[str, Any], paths: List[Dict[str, List[str]]]) -> List[str]:
    missing = []
    for path_obj in paths:
        path = path_obj.get("path")
        if not path:
            continue
        current = data
        try:
            for key in path:
                current = current[key]
        except (KeyError, TypeError, IndexError):
            missing.append(".".join(path) if isinstance(path, list) else str(path))
    return missing


def paths_for_claim_sets(
    claims: Sequence[Any],
    claim_sets: Optional[Sequence[Sequence[str]]],
    data: Dict[str, Any],
) -> List[Dict[str, List[str]]]:
    """
    Resolve the claim paths to extract for a credential query.

    Without claim_sets, every claim path is required. With claim_sets, the first
    fully satisfied set (RP preference order) is selected.
    """
    by_id = {}
    for index, claim in enumerate(claims or []):
        path = _claim_path(claim)
        if not path:
            continue
        by_id[_claim_id(claim, index)] = {"path": path}

    if not claim_sets:
        return list(by_id.values())

    first_missing: Optional[List[str]] = None
    for claim_set in claim_sets:
        if not isinstance(claim_set, (list, tuple)):
            continue
        paths = []
        unresolved = []
        for claim_id in claim_set:
            path_obj = by_id.get(claim_id)
            if not path_obj:
                unresolved.append(str(claim_id))
                continue
            paths.append(path_obj)
        missing = unresolved + _missing_paths(data, paths)
        if not missing:
            return paths
        if first_missing is None:
            first_missing = missing

    raise ValueError(f"Missing claims: {', '.join(first_missing or [])}")


def extract_claims(
    data: Dict[str, Any], paths: List[Dict[str, List[str]]]
) -> Dict[str, Any]:
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
    missing = _missing_paths(data, paths)

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
                continue
        else:
            # fallback for flat single-key paths (e.g. path=["given_name"])
            try:
                value = data[path[0]]
                result[path[0]] = value
            except (KeyError, TypeError, IndexError):
                continue

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
