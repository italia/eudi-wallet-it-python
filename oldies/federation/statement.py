def jwks_from_jwks_uri(jwks_uri: str, httpc_params: dict, http_async: bool = True) -> list[dict]:
    """
    Retrieves jwks from an entity uri.

    :param jwks_uri: the uri where the jwks are located.
    :type jwks_uri: str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param http_async: if is set to True the operation will be performed in async (deafault True)
    :type http_async: bool

    :returns: A list of entity jwks.
    :rtype: list[dict]
    """

    response = get_http_url(jwks_uri, httpc_params, http_async)
    jwks = [i.json() for i in response]

    return jwks