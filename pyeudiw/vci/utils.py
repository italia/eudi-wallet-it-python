from functools import lru_cache
from urllib.parse import ParseResult, urlparse

import requests

from pyeudiw.tools.utils import get_http_url


def final_issuer_endpoint(issuer: str, wk_endpoint: str) -> str:
    """Prepend the wk_endpoint part tot he path of the issuer.
    For example, if the issuer is 'https://example.com/tenant/1234' and the
    well known endpoint is '/.well-known/jwt-vc-issuer', then the final
    endpoint will be
    'https://example.com/.well-known/jwt-vc-issuer/tenant/1234'
    """
    baseurl = urlparse(issuer)
    well_known_path = wk_endpoint + baseurl.path
    well_known_url: str = ParseResult(baseurl.scheme, baseurl.netloc, well_known_path, baseurl.params, baseurl.query, baseurl.fragment).geturl()
    return well_known_url


@lru_cache
def cacheable_get_http_url(ttl_cache: int, urls: list[str] | str, httpc_params: dict, http_async: bool = True) -> list[requests.Response]:
    """
    wraps method 'get_http_url' around a ttl cache
    """
    del ttl_cache
    return get_http_url(urls, httpc_params, http_async)
