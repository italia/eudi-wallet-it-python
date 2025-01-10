from urllib.parse import quote_plus, urlencode


def build_authorization_request_url(scheme: str, params: dict) -> str:
    """
    Build authorization request URL that let the wallet download the request
    object. This is loosely realted to RFC9101 [JAR], section 5.2.1.
    The scheme is either the scheme portion of a deeplink, such as "haip" or
    "eudiw", while params is a dictitonary of query parameters not urlencoded.
    """
    if "://" not in scheme:
        scheme = scheme + "://"
    query_params = urlencode(params, quote_via=quote_plus)
    _sep = "" if "?" in scheme else "?"
    return f"{scheme}{_sep}{query_params}"
