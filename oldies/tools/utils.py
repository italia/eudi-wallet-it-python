def get_jwks(
    httpc_params: dict, metadata: dict, federation_jwks: list[dict] = []
) -> dict:
    """
    Get jwks or jwks_uri or signed_jwks_uri

    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param metadata: metadata of the entity
    :type metadata: dict
    :param federation_jwks: jwks of the federation
    :type federation_jwks: list

    :returns: A list of responses.
    :rtype: list[dict]
    """
    jwks_list = []
    if metadata.get("jwks"):
        jwks_list = metadata["jwks"]["keys"]
    elif metadata.get("jwks_uri"):
        try:
            jwks_uri = metadata["jwks_uri"]
            jwks_list = get_http_url([jwks_uri], httpc_params=httpc_params)
            jwks_list = jwks_list[0].json()
        except Exception as e:
            logger.error(f"Failed to download jwks from {jwks_uri}: {e}")
    elif metadata.get("signed_jwks_uri"):
        try:
            signed_jwks_uri = metadata["signed_jwks_uri"]
            jwks_list = get_http_url([signed_jwks_uri], httpc_params=httpc_params)[
                0
            ].json()
        except Exception as e:
            logger.error(f"Failed to download jwks from {signed_jwks_uri}: {e}")
    return jwks_list

def satisfy_interface(o: object, interface: type) -> bool:
    """
    Returns true if and only if an object satisfy an interface.

    :param o: an object (instance of a class)
    :type o: object
    :param interface: an interface type
    :type interface: type

    :returns: True if the object satisfy the interface, otherwise False
    """
    for cls_attr in dir(interface):
        if cls_attr.startswith("_"):
            continue
        if not hasattr(o, cls_attr):
            return False
        if callable(getattr(interface, cls_attr)) and not callable(
            getattr(o, cls_attr)
        ):
            return False
    return True