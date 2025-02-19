from urllib.parse import quote_plus, urlencode

def _build_authz_request_url(self, payload: dict) -> str:
    scheme = self.config["authorization"]["url_scheme"]
    if "://" not in scheme:
        scheme = scheme + "://"
    if not scheme.endswith("/"):
        scheme = f"{scheme}/"
    # NOTE: path component is currently unused by the protocol, but currently
    # we leave it there as 'authorize' to stress the fact that this is an
    # OAuth 2.0 request modified by JAR (RFC9101)
    path = "authorize"
    query_params = urlencode(payload, quote_via=quote_plus)
    return f"{scheme}{path}?{query_params}"