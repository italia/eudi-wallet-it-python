from datetime import timezone
# from django.utils.timezone import make_aware
from secrets import token_hex

from . jwt import unpad_jwt_header


import datetime
import json
import logging

logger = logging.getLogger(__name__)


def make_timezone_aware(dt: datetime.datetime):
    # TODO
    raise NotImplementedError(f"{__name__} make_timezone_aware")


def iat_now() -> int:
    return int(datetime.datetime.now().timestamp())


def exp_from_now(minutes: int = 33) -> int:
    _now = timezone.localtime()
    return int((_now + datetime.timedelta(minutes=minutes)).timestamp())


def datetime_from_timestamp(value) -> datetime.datetime:
    return make_timezone_aware(datetime.datetime.fromtimestamp(value))


def get_http_url(url: str):
    # TODO
    raise NotImplementedError(f"{__name__} get_http_url")


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


def get_jwk_from_jwt(jwt: str, provider_jwks: dict) -> dict:
    """
        docs here
    """
    head = unpad_jwt_header(jwt)
    kid = head["kid"]
    if isinstance(provider_jwks, dict) and provider_jwks.get('keys'):
        provider_jwks = provider_jwks['keys']
    for jwk in provider_jwks:
        if jwk["kid"] == kid:
            return jwk
    return {}


def random_token(n=254):
    return token_hex(n)
