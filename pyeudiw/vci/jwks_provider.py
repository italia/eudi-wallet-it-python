import time
from typing import Literal

from pyeudiw.tools.utils import get_http_url
from pyeudiw.vci.utils import cacheable_get_http_url, final_issuer_endpoint

DEFAULT_ENDPOINT = "/.well-known/jwt-vc-issuer"
DEFAULT_TTL_CACHE = 60 * 60  # in seconds, hence 1 hour


class VciJwksSource:
    """VciJwksSource is an interface that provides a jwk set for verifiable credential issuer
    """
    def get_jwks(self, issuer: str) -> dict:
        raise NotImplementedError


class RemoteVciJwksSource(VciJwksSource):

    def __init__(self, httpc_params: dict, endpoint: str = DEFAULT_ENDPOINT):
        self.httpc_params = httpc_params
        self.endpoint = endpoint

    def _verify_response_issuer(self, exp_issuer: str, response_json: dict) -> None:
        if exp_issuer != (obt_issuer := response_json.get("issuer", "")):
            raise Exception(f"invalid issuing key metadata: expected issuer {exp_issuer}, obtained {obt_issuer}")

    def _get_jwk_metadata(self, uri: str) -> dict:
        try:
            # TODO: sistemare httpc params
            resp = get_http_url(uri, {"connection": {"ssl": False}, "session": {"timeout": 6}}, http_async=False)
            response: dict = resp[0].json()
            return response
        except Exception as e:
            # TODO: handle meaningfully
            raise e

    def _get_jwkset_from_jwkset_uri(self, jwkset_uri: str) -> list[dict]:
        try:
            # TODO: sistemare httpc params
            resp = get_http_url(jwkset_uri, {"connection": {"ssl": False}, "session": {"timeout": 6}}, http_async=False)
            jwks: dict[Literal["keys"], list[dict]] = resp[0].json()
            return jwks.get("keys", [])
        except Exception as e:
            # TODO; handle meaningfully
            raise e

    def _obtain_jwkset_from_response_json(self, response: dict) -> list[dict]:
        jwks: dict[Literal["keys"], list[dict]] = response.get("jwks", None)
        jwks_uri = response.get("jwks_uri", None)
        if (not jwks) and (not jwks_uri):
            raise Exception("invalid issuing key metadata: missing both claims [jwks] and [jwks_uri]")
        if jwks:
            return jwks.get("keys", [])
        return self._get_jwkset_from_jwkset_uri(jwks_uri)

    def get_jwks(self, issuer: str) -> list[dict]:
        well_known_url = final_issuer_endpoint(issuer, self.endpoint)
        resp_data = self._get_jwk_metadata(well_known_url)
        self._verify_response_issuer(issuer, resp_data)
        return self._obtain_jwkset_from_response_json(resp_data)


class CachedVciJwksSource(RemoteVciJwksSource):

    def __init__(self, ttl_cache: int = DEFAULT_TTL_CACHE, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ttl_cache = ttl_cache

    def _get_jwk_metadata(self, uri: str) -> dict:
        ttl_timestamp = round(time.time() / self.ttl_cache)
        try:
            resp = cacheable_get_http_url(ttl_timestamp, uri, self.httpc_params)
            response: dict = resp[0].json()
            return response
        except Exception:
            # TODO: handle exception
            pass

    def _get_jwkset_from_jwkset_uri(self, jwkset_uri: str) -> list[dict]:
        ttl_timestamp = round(time.time() / self.ttl_cache)
        try:
            resp = cacheable_get_http_url(ttl_timestamp. jwkset_uri, self.httpc_params)
            jwks: dict[Literal["keys"], list[dict]] = resp[0].json()
            return jwks.get("keys", [])
        except Exception:
            # TODO: handle exception
            pass

    def _obtain_jwkset_from_response_json(self, response: dict) -> list[dict]:
        jwks: dict[Literal["keys"], list[dict]] = response.get("jwks", None)
        jwks_uri = response.get("jwks_uri", None)
        if (not jwks) and (not jwks_uri):
            raise Exception("invalid issuing key metadata: missing both claims [jwks] and [jwks_uri]")
        if jwks:
            return jwks.get("keys", [])
        try:
            ttl_timestamp = round(time.time() / self.ttl_cache)
            resp = cacheable_get_http_url(ttl_timestamp, jwks_uri, self.httpc_params)
            jwks = resp[0].json()
            return jwks.get("keys", [])
        except Exception:
            # TODO: handle exception
            pass

    def get_jwks(self, issuer: str) -> list[dict]:
        return super().get_jwks(issuer)
