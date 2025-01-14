import json
from typing import Any, Callable

from urllib.parse import urlparse

from pyeudiw.jwk import JWK
import satosa.context
import satosa.response
from pyeudiw.satosa.utils.response import JsonResponse

from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc


DEFAULT_JARISSUER_METADATA_ENDPOINT = "/.well-known/jar-issuer"
"""Default endpoint adopted by potential interopebility document as of version 1.1.
The endpopint should be positioned between the host component and the path component (if any) of the iss claim value in the JAR.
"""


class DirectTrustJar(DirectTrustSdJwtVc):
    """
    DirectTrustJar extends DirectTrustSdJwtVC model to include exposure of \
    metadata information at a given known endpoint.

    Attributes:
        jwks: list off private keys thgat can be used to permorm cryptographic \
            operation; each list element is a dicctionary that represent a jwk.
        jar_issuer_endpoint: partial path component that identify which path \
            component specify this endpoint.
        **kwargs: parent class attributes initialized at constructor as decribed in \
            pyeudiw.trust.handler.direct_trust_sd_jwt_vc.DirectTrustSdJwtVc
    """

    def __init__(self, jwks: list[dict], jar_issuer_endpoint: str = DEFAULT_JARISSUER_METADATA_ENDPOINT, **kwargs):
        super().__init__(**kwargs)
        try:
            [JWK(key=key) for key in jwks]
        except Exception as e:
            raise ValueError("invalid argument: dictionary is not a jwk", e)
        self.jwks = jwks
        self.jar_issuer_endpoint = jar_issuer_endpoint

    def _build_public_signing_jwks(self) -> list[dict]:
        signing_keys = [
            key for key in self.jwks if key.get("use", "") != "enc"]
        return [
            JWK(key).as_public_dict() for key in signing_keys
        ]

    def _build_jar_issuer_metadata(self, entity_id: str) -> dict:
        # This funciton assumed that the issuer is equal to the entity_uri; this
        #  is currently an implementation detail and might not hold in the future;
        # This could also be resolved by extrating the request uri from the satosa
        #  context; but for not we will opt for the simple option.
        md_dictionary = {
            "iss": entity_id,
            "jwks": {
                "keys": self._build_public_signing_jwks()
            }
        }
        return md_dictionary

    def _build_metadata_path(self, backend_name: str) -> str:
        """
        If the entity URI is https://<hotst>/<path>, then the built metadata
        path will be <path>/.well-known/jar-issuer (or the equivalent
        configured terminating portion).

        IMPORTANT: If the path that should be exposed MUST start with
        `/.well-known/`, then that issue must be solved at the wsgi-nginx
        level as it breaks an assuptions of the internal satosa router and
        there is no way to solve that problem at the satosa backend level.
        """
        endpoint = backend_name.strip('/') + '/' + self.jar_issuer_endpoint.strip("/")
        return endpoint.strip('/')

    def build_metadata_endpoints(self, backend_name: str, entity_uri: str) -> list[tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]:
        metadata_path = '^' + self._build_metadata_path(backend_name) + '$'
        response_json = self._build_jar_issuer_metadata(entity_uri)

        def metadata_response_fn(ctx: satosa.context.Context, *args) -> satosa.response.Response:
            return JsonResponse(message=response_json)
        return [(metadata_path, metadata_response_fn)]
