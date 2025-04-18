from pyeudiw.jwk import JWK
from pyeudiw.trust.handler._direct_trust_jwk import _DirectTrustJwkHandler
from pyeudiw.trust.model.trust_source import TrustEvaluationType, TrustSourceData

from .commons import DEFAULT_HTTPC_PARAMS

DEFAULT_JARISSUER_METADATA_ENDPOINT = "/.well-known/jar-issuer"
"""Default endpoint adopted by potential interopebility document as of version 1.1.
The endpopint should be positioned between the host component and the path component (if any) of the iss claim value in the JAR.
"""


class DirectTrustJar(_DirectTrustJwkHandler):
    """DirectTrustJar is specialization of _DirectTrustJwkHandler
    used in the context of JAR (RFC9101).
    """

    def __init__(
        self,
        httpc_params: dict = DEFAULT_HTTPC_PARAMS,
        jwk_endpoint: str = DEFAULT_JARISSUER_METADATA_ENDPOINT,
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

    def _extract_and_update_own_trust_material(self, trust_source: TrustSourceData) -> TrustSourceData:
        if self.jwks is None:
            return trust_source

        public_keys = [JWK(k).as_public_dict() for k in self.jwks]

        trust_source.add_trust_param(
            self.get_handled_trust_material_name(),
            TrustEvaluationType(
                attribute_name="jwks",
                jwks=public_keys,
                expiration_date=None,
                trust_handler_name=str(self.__class__.__name__),
            )
        )
        return trust_source

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        # In the context of an OID4VP protocol flow, no-one but ourself
        # can be trusted as a JAR issuer. As long as this is true, we have
        # no reason to collect other parties JAR trust material.
        if issuer != self.client_id:
            return trust_source
        return self._extract_and_update_own_trust_material(trust_source)

    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
        # NOTE: as of version 1 of Potential profile for OID4VP, there is
        # no such thing as online resolution of client metadata outside of
        # what already defined in different schemes OID4VP draft 21 section 5,
        # where the usage of client_metadata parameter in the presentation
        # request is suggested
        return trust_source

    def get_handled_trust_material_name(self) -> str:
        return "direct_trust_jar"
