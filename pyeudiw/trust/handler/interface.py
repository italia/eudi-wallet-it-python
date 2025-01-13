from typing import Any, Callable
import satosa.context
import satosa.response

from pyeudiw.trust.model.trust_source import TrustSourceData


class TrustHandlerInterface:
    def extract_and_update_trust_materials(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        """
        Extract the trust material of a certain issuer using a trust handler implementation.

        :param issuer: The issuer
        :type issuer: str
        :param trust_source: The trust source to update
        :type trust_source: TrustSourceData

        :returns: The updated trust source
        :rtype: TrustSourceData
        """
        raise NotImplementedError

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        """
        Get the metadata of a certain issuer if is needed by the specifics.

        :param issuer: The issuer
        :type issuer: str
        :param trust_source: The trust source to update
        :type trust_source: TrustSourceData
        
        :returns: The updated trust source
        :rtype: TrustSourceData
        """

        raise NotImplementedError

    def build_metadata_endpoints(self, entity_uri: str) -> list[tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]:
        """
        Expose one or more metadata endpoint required to publish metadata
        information about *myself* and that are associated to a trust
        mechanism, such as public keys, configurations, policies, etc.

        The result of this method is a list of element where each one is of type
        ```
            tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]
        ```
        compliant to satosa.backend.BackendModule method register_endpoints, that is:
        1. the first argument is a regxp used for rotuing to that endpoint; while \
            not required, this regexpt is likely to use the base_path argument
        2. the second argument is an http handler that can provide a response given \
            the information in the context.

        The entity_uri is the full path component of the exposed satosa module.
        We assume that the module is exposed to the outside web according to
        the follwing pattern
            <scheme>://<host>/<base_path>

        The base path information might be required for appropriate routing. For
        example, if the satosa entity is known to the outside element of a trust
        network as
            http://satosa.example/openid4vp,
        then some trust frameworks might require to publish a well known information
        at endpoint
            http://satosa.exammple/openid4vp/.well-known/protocol-config
        while other protocols might require to register
            http://satosa.exammple/.well-known/protocol-config/openid4vp

        The TrustHandler might not have any associated metadata endpoint, in which case
        an empty list is returned instead.
        """
        return []

    @property
    def name(self) -> str:
        """
        Return the name of the trust handler.

        :returns: The name of the trust handler
        :rtype: str
        """
        return self.__class__.__name__
