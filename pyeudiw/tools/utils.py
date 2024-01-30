import datetime
import logging
import asyncio
import requests
import importlib

from secrets import token_hex
from pyeudiw.federation.http_client import http_get_sync, http_get_async

logger = logging.getLogger(__name__)


def make_timezone_aware(dt: datetime.datetime, tz: datetime.timezone | datetime.tzinfo = datetime.timezone.utc) -> datetime.datetime:
    """
    Make a datetime timezone aware.

    :param dt: The datetime to make timezone aware
    :type dt: datetime.datetime
    :param tz: The timezone to use
    :type tz: datetime.timezone | datetime.tzinfo

    :returns: The timezone aware datetime
    :rtype: datetime.datetime
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)
    else:
        raise ValueError("datetime is already timezone aware")


def iat_now() -> int:
    """
    Get the current timestamp in seconds.

    :returns: The current timestamp in seconds
    :rtype: int
    """
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())


def exp_from_now(minutes: int = 33) -> int:
    """
    Get the expiration timestamp in seconds for the given minutes from now.

    :param minutes: The minutes from now
    :type minutes: int

    :returns: The timestamp in seconds for the given minutes from now
    :rtype: int
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    return int((now + datetime.timedelta(minutes=minutes)).timestamp())


def datetime_from_timestamp(timestamp: int | float) -> datetime.datetime:
    """
    Get a datetime from a timestamp.

    :param value: The timestamp
    :type value: int | float

    :returns: The datetime
    :rtype: datetime.datetime
    """

    return make_timezone_aware(datetime.datetime.fromtimestamp(timestamp))


def get_http_url(urls: list[str] | str, httpc_params: dict, http_async: bool = True) -> list[requests.Response]:
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
            http_get_async(urls, httpc_params))  # pragma: no cover
    else:
        responses = http_get_sync(urls, httpc_params)
    return responses


def get_jwks(httpc_params: dict, metadata: dict, federation_jwks: list[dict] = []) -> dict:
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
    if metadata.get('jwks'):
        jwks_list = metadata["jwks"]["keys"]
    elif metadata.get('jwks_uri'):
        try:
            jwks_uri = metadata["jwks_uri"]
            jwks_list = get_http_url(
                [jwks_uri], httpc_params=httpc_params
            )
            jwks_list = jwks_list[0].json()
        except Exception as e:
            logger.error(f"Failed to download jwks from {jwks_uri}: {e}")
    elif metadata.get('signed_jwks_uri'):
        try:
            signed_jwks_uri = metadata["signed_jwks_uri"]
            jwks_list = get_http_url(
                [signed_jwks_uri], httpc_params=httpc_params
            )[0].json()
        except Exception as e:
            logger.error(
                f"Failed to download jwks from {signed_jwks_uri}: {e}")
    return jwks_list


def random_token(n=254) -> str:
    """
    Generate a random token.

    :param n: The length of the token
    :type n: int

    :returns: The random token
    :rtype: str
    """
    return token_hex(n)


def get_dynamic_class(module_name: str, class_name: str) -> object:
    """
    Get a class instance dynamically.

    :param module_name: The name of the module
    :type module_name: str
    :param class_name: The name of the class
    :type class_name: str

    :returns: The class instance
    :rtype: object
    """

    module = importlib.import_module(module_name)
    instance_class = getattr(module, class_name)
    return instance_class


def dynamic_class_loader(module_name: str, class_name: str, init_params: dict = {}) -> object:
    """
    Load a class dynamically.

    :param module_name: The name of the module
    :type module_name: str
    :param class_name: The name of the class
    :type class_name: str
    :param init_params: The parameters to pass to the class constructor
    :type init_params: dict

    :returns: The class instance
    :rtype: object
    """

    storage_instance = get_dynamic_class(
        module_name, class_name)(**init_params)
    return storage_instance
