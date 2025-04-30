import re
import requests
from typing import Any, Callable, Literal
from urllib.parse import urlparse

import satosa.context
import satosa.response

from pyeudiw.jwk import JWK
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import cacheable_get_http_url, get_http_url
from pyeudiw.trust.handler.exception import InvalidJwkMetadataException
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustEvaluationType


class _DirectTrustJwkHandler(TrustHandlerInterface, BaseLogger):
    """
    This is class used to group common logic among classes that fetch of expose
    cryptogrpahic material in the form of a JWKS (Json Web Kwy Set) at a known
    endpoint, which is usually a /.well-known endpoint.

    It assumes that exposed in the protocol-defined endpoints is trusted even
    when it is not backed up by a proper trust attestation leading to a known and
    recognized root of trust.

    _DirectTrustJwkHandler supports an simple in memory LRU (least recently used)
    cache with expiration.

    Attributes:
        httpc_params: connection parameters used to make http requests, if required.
        jwk_endpoint: endpoint component used to publish own public keys or to \
            fetch other entities keys; usually in the form of a /.well-known.
        cache_ttl: maximum cache duration, in seconds.
        jwks: list of private keys (possible none) that are owned by the trust \
            evaluation mechanism and that might be exposes when presenting to \
            the others as token issuer.
    """

    def __init__(
        self,
        httpc_params: dict,
        jwk_endpoint: str,
        cache_ttl: int,
        jwks: list[dict] | None,
        client_id: str = None,
    ):
        self.httpc_params = httpc_params
        self.jwk_endpoint = jwk_endpoint
        self.cache_ttl = cache_ttl
        self.http_async_calls = False
        self.client_id = client_id
        # input validation
        self.jwks = jwks if jwks else []
        try:
            [JWK(key=key) for key in self.jwks]
        except Exception as e:
            raise ValueError("invalid argument: dictionary is not a jwk", e)

    def _build_issuing_public_signing_jwks(self) -> list[dict]:
        signing_keys = [key for key in self.jwks if key.get("use", "") != "enc"]
        return [JWK(key).as_public_dict() for key in signing_keys]

    def _build_metadata_with_issuer_jwk(self, entity_id: str) -> dict:
        # This funciton assumed that the issuer is equal to the entity_uri; this
        #  is currently an implementation detail and might not hold in the future;
        # This could also be resolved by extrating the request uri from the satosa
        #  context; but for not we will opt for the simple option.
        md_dictionary = {
            "issuer": entity_id,
            "jwks": {"keys": self._build_issuing_public_signing_jwks()},
        }
        return md_dictionary

    def _build_metadata_path(self, backend_name: str) -> str:
        """
        If the entity URI is https://<hotst>/<path>, then the built metadata
        path will be <path>/.well-known/jar-issuer (or the equivalent
        configured terminating portion <path>/<jwk_endpoint>).

        IMPORTANT: If the path that should be exposed MUST start with
        `/.well-known/`, then that issue must be solved at the wsgi-nginx
        level as it breaks an assuptions of the internal satosa router and
        there is no way to solve that problem at the satosa backend level.
        """
        endpoint = f"{backend_name.strip('/')}/{self.jwk_endpoint.strip('/')}"
        return endpoint.strip("/")

    def _extract_jwks_from_jwk_metadata(self, metadata: dict) -> dict:
        """
        parse the jwk metadata document and return the jwks
        NOTE: jwks might be in the document by value or by reference
        """
        jwks: dict[Literal["keys"], list[dict]] | None = metadata.get("jwks", None)
        jwks_uri: str | None = metadata.get("jwks_uri", None)
        if (not jwks) and (not jwks_uri):
            raise InvalidJwkMetadataException(
                "invalid issuing key metadata: missing both claims [jwks] and [jwks_uri]"
            )
        if jwks:
            # get jwks by value
            return jwks
        jwks_resp = self._get_jwks_by_reference(jwks_uri)
        if jwks_resp and jwks_resp.status_code == 200:
            return jwks_resp.json()
    
    def _get_url(self, endpoint: str) -> requests.Response:
        if self.cache_ttl:
            resp = cacheable_get_http_url(
                self.cache_ttl,
                endpoint,
                self.httpc_params,
                http_async=self.http_async_calls,
            )
        else:
            resp = get_http_url(
                [endpoint], self.httpc_params, http_async=self.http_async_calls
            )[0]

        return resp

    def _get_jwk_metadata(self, issuer_id: str) -> dict:
        if not self.jwk_endpoint:
            return {}
        
        endpoints = [
            build_jwk_issuer_endpoint(issuer_id, self.jwk_endpoint),
            build_jwk_issuer_endpoint(issuer_id, self.jwk_endpoint, conform=False),
        ]

        for endpoint in endpoints:
            resp = self._get_url(endpoint)

            if resp and resp.status_code == 200:
                return resp.json()

        raise InvalidJwkMetadataException(
            f"failed to fetch valid jwk metadata: obtained {resp}"
        )

    def _get_jwks_by_reference(self, jwks_reference_uri: str) -> requests.Response:
        """
        call the jwks endpoint if jwks is defined by reference
        """
        return self._get_url(jwks_reference_uri)

    def build_metadata_endpoints(
        self, backend_name: str, entity_uri: str
    ) -> list[
        tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]
    ]:
        if not self.jwk_endpoint:
            return []

        metadata_path = "^" + self._build_metadata_path(backend_name) + "$"
        response_json = self._build_metadata_with_issuer_jwk(entity_uri)

        def metadata_response_fn(
            ctx: satosa.context.Context, *args
        ) -> satosa.response.Response:
            return JsonResponse(message=response_json)

        return [(metadata_path, metadata_response_fn)]

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        """
        Fetches the public key of the issuer by querying a given endpoint.
        Previous responses might or might not be cached based on the cache_ttl
        parameter.

        :returns: a list of jwk(s)
        """
        if not issuer:
            raise ValueError("invalid issuer: cannot be empty value")

        if not is_url(issuer):
            self._log_warning("Extracting JWK", f"invalid issuer: issuer should be an URL, observed instead {issuer}")
            return trust_source

        try:
            self.get_metadata(issuer, trust_source)
        except Exception as e:
            self._log_warning(
                "updating metadata",
                f"Exception encountered when updating metadata with {self.__class__.__name__} for issuer {issuer}: {e}",
            )

        try:
            md = self._get_jwk_metadata(issuer)
            if not issuer == (obt_issuer := md.get("issuer", None)):
                raise InvalidJwkMetadataException(
                    f"invalid jwk metadata: obtained issuer :{obt_issuer}, expected issuer: {issuer}"
                )
            jwks = self._extract_jwks_from_jwk_metadata(md)
            jwk_l: list[dict] = jwks.get("keys", [])
            if not jwk_l:
                raise InvalidJwkMetadataException(
                    "unable to find jwks in issuer jwk metadata"
                )

            trust_source.add_trust_param(
                "direct_trust_sd_jwt_vc",
                TrustEvaluationType(
                    attribute_name="jwks",
                    jwks=[JWK(key=jwk).as_dict() for jwk in jwk_l],
                    expiration_date=None,
                    trust_handler_name=str(self.__class__.__name__),
                )
            )
        except Exception as e:
            self._log_warning(
                "Extracting JWK", f"Failed to extract jwks from issuer {issuer}: {e}"
            )

        return trust_source
    
    def validate_trust_material(
            self, 
            trust_chain: list[str], 
            trust_source: TrustSourceData,
            db_engine: DBEngine
        ) -> tuple[bool, TrustSourceData]:
        """
        Validate the trust material of the trust source.
        """
        return False, trust_source
    
    def get_handled_trust_material_name(self) -> str:
        """
        Return the name of the trust material that is handled by the trust handler.
        """
        return "direct_trust_sd_jwt_vc"

    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        # this class does not handle generic metadata information: it fetches and exposes cryptographic material only
        return trust_source

    def extract_jwt_header_trust_parameters(self, trust_source: TrustSourceData) -> dict:
        """
        Direct Trust is not formally associated to any trust parameter
        """
        return {}


def build_jwk_issuer_endpoint(issuer_id: str, endpoint_component: str, conform: bool = True) -> str:
    if not endpoint_component:
        return issuer_id

    issuer_id = f"https://{issuer_id.strip('/')}" if not issuer_id.startswith("http") else issuer_id

    baseurl = urlparse(issuer_id)
    full_endpoint_path = f"/{endpoint_component.strip('/')}{baseurl.path}" if conform else f"{baseurl.path}/{endpoint_component.strip('/')}"
    return baseurl._replace(path=full_endpoint_path).geturl()


# this is the regular expression that django uses for URL validation
_is_url_regex = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
    r'localhost|' #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def is_url(url: str) -> bool:
    if not _is_url_regex.search(url):
        return False
    return True
