from typing import List, Dict, Any

from pyeudiw.duckle_ql.credential import MSO_MDOC_FORMAT


def _flatten_mso_mdoc(d) -> Dict[str, Any]:
    """
    Recursively flattens a nested dictionary representing MSO mdoc namespace data.

    This function traverses all levels of the input dictionary and merges nested keys into a single-level dictionary.
    If a key appears more than once with different values, a ValueError is raised to signal a conflict.

    Args:
        d (dict): A (potentially nested) dictionary representing a namespace's attributes.

    Returns:
        Dict[str, Any]: A flat dictionary with all nested key-value pairs merged.

    Raises:
        ValueError: If the same key appears with conflicting values in the nested structure.
    """
    result: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            inner = _flatten_mso_mdoc(v)
            for inner_k, inner_v in inner.items():
                if inner_k in result and result[inner_k] != inner_v:
                    raise ValueError(f"Key conflict: '{inner_k}' has conflicting values '{result[inner_k]}' and '{inner_v}'")
                result[inner_k] = inner_v
        else:
            if k in result and result[k] != v:
                raise ValueError(f"Key conflict: '{k}' has conflicting values '{result[k]}' and '{v}'")
            result[k] = v
    return result


def map_attribute(data_list: List) -> Dict[str, Any]:
    """
    Extracts and merges attributes from MSO mdoc credentials in a data list.

    This function filters the input list for credentials with the MSO_MDOC_FORMAT format,
    flattens each of their namespace dictionaries, and merges the resulting key-value pairs
    into a single dictionary. Conflicts in key values across credentials raise a ValueError.

    Args:
        data_list (List[Dict[str, Any]]): A list of credential dictionaries, potentially containing
                                          multiple formats and nested namespace data.

    Returns:
        Dict[str, Any]: A single flat dictionary containing merged attributes from MSO mdoc credentials.

    Raises:
        ValueError: If duplicate keys with different values are encountered during the merge.
    """
    flat_result: Dict[str, Any] = {}
    for cred in data_list:
        if cred.get("credential_format") == MSO_MDOC_FORMAT:
            for ns_data in cred.get("namespaces", {}).values():
                ns_flat = _flatten_mso_mdoc(ns_data)
                for k, v in ns_flat.items():
                    if k in flat_result:
                        if flat_result[k] != v:
                            raise ValueError(f"Key conflict: '{k}' has conflicting values '{flat_result[k]}' and '{v}'")
                    else:
                        flat_result[k] = v
    return flat_result
