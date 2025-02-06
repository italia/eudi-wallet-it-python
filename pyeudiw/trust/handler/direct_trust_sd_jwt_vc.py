from pyeudiw.tools.utils import cacheable_get_http_url, get_http_url
from pyeudiw.trust.handler._direct_trust_jwk import _DirectTrustJwkHandler
from pyeudiw.trust.model.trust_source import TrustSourceData

from .commons import DEFAULT_HTTPC_PARAMS, DEFAULT_OPENID4VCI_METADATA_ENDPOINT

DEFAULT_SDJWTVC_METADATA_ENDPOINT = "/.well-known/jwt-vc-issuer"
"""Default endpoint where issuer keys used for sd-jwt vc are exposed.
For further reference, see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-06.html#name-jwt-vc-issuer-metadata
"""


class DirectTrustSdJwtVc(_DirectTrustJwkHandler):
    """DirectTrustSdJwtVc is specialization of _DirectTrustJwkHandler
    used in the context of sd-jwt for verifiable credentials.
    """

    def __init__(
        self,
        httpc_params: dict = DEFAULT_HTTPC_PARAMS,
        jwk_endpoint: str = DEFAULT_SDJWTVC_METADATA_ENDPOINT,
        metadata_endpoint: str = DEFAULT_OPENID4VCI_METADATA_ENDPOINT,
        cache_ttl: int = 0,
        jwks: list[dict] | None = None,
        client_id: str = None,
    ):
        super().__init__(
            httpc_params=httpc_params,
            jwk_endpoint=jwk_endpoint,
            cache_ttl=cache_ttl,
            jwks=jwks,
            client_id=client_id,
        )
        self.metadata_endpoint = metadata_endpoint

    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        """
        Fetches the public metadata of an issuer by interrogating a given
        endpoint. The endpoint must yield information in a format that
        can be transalted to a meaning dictionary (such as json)

        :returns: a dictionary of metadata information
        """
        url = build_metadata_issuer_endpoint(issuer, self.metadata_endpoint)
        if self.cache_ttl == 0:
            trust_source.metadata = get_http_url(
                url, self.httpc_params, self.http_async_calls
            )[0].json()
        else:
            trust_source.metadata = cacheable_get_http_url(
                self.cache_ttl, url, self.httpc_params, self.http_async_calls
            ).json()

        return trust_source


# TODO: do you really think that this should be stay here?


def build_metadata_issuer_endpoint(issuer_id: str, endpoint_component: str) -> str:
    return f"{issuer_id.rstrip('/')}/{endpoint_component.lstrip('/')}"
