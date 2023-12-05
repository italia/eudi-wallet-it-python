import datetime
import json
import logging
import asyncio
import requests

from secrets import token_hex
from pyeudiw.federation.http_client import http_get

logger = logging.getLogger(__name__)


def make_timezone_aware(dt: datetime.datetime, tz: datetime.timezone | datetime.tzinfo = datetime.timezone.utc):
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)
    else:
        raise ValueError("datetime is already timezone aware")


def iat_now() -> int:
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())


def exp_from_now(minutes: int = 33) -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    return int((now + datetime.timedelta(minutes=minutes)).timestamp())


def datetime_from_timestamp(value) -> datetime.datetime:
    return make_timezone_aware(datetime.datetime.fromtimestamp(value))


def get_http_url(urls: list[str] | str, httpc_params: dict, http_async: bool = True) -> list[dict]:
    """
    Perform an HTTP Request returning the payload of the call.

    :param urls: The url or a list of url where perform the GET HTTP calls
    :type urls: list[str] | str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param http_async: if is set to True the operation will be performed in async (deafault True)
    :type http_async: bool

    :returns: A list of responses.
    :rtype: list[dict]
    """
    urls = urls if isinstance(urls, list) else [urls]

    if http_async:
        responses = asyncio.run(
            http_get(urls, httpc_params))  # pragma: no cover
    else:
        responses = []
        for i in urls:
            res = requests.get(i, **httpc_params)  # nosec - B113
            responses.append(res.content)
    return responses


def get_jwks(httpc_params: dict, metadata: dict, federation_jwks: list = []) -> dict:
    """
    get jwks or jwks_uri or signed_jwks_uri
    """
    jwks_list = []
    if metadata.get('jwks'):
        jwks_list = metadata["jwks"]["keys"]
    elif metadata.get('jwks_uri'):
        try:
            jwks_uri = metadata["jwks_uri"]
            jwks_list = get_http_url(
                [jwks_uri], httpc_params=httpc_params
            )
            jwks_list = json.loads(jwks_list[0])
        except Exception as e:
            logger.error(f"Failed to download jwks from {jwks_uri}: {e}")
    elif metadata.get('signed_jwks_uri'):
        try:
            signed_jwks_uri = metadata["signed_jwks_uri"]
            jwks_list = get_http_url(
                [signed_jwks_uri], httpc_params=httpc_params
            )[0]
        except Exception as e:
            logger.error(
                f"Failed to download jwks from {signed_jwks_uri}: {e}")
    return jwks_list


def random_token(n=254):
    return token_hex(n)
