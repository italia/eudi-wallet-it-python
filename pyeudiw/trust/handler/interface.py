from typing import Any, Callable, List, Optional, Tuple

from satosa.context import Context
from satosa.response import Response

from pyeudiw.trust.model.trust_source import TrustSourceData


class TrustHandlerInterface:
    def __init__(self, *args, **kwargs):
        self.client_id = kwargs.get("client_id", "default_client_id")

    def extract_and_update_trust_materials(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
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

    def get_metadata(
        self, issuer: str, trust_source: TrustSourceData
    ) -> TrustSourceData:
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

    def build_metadata_endpoints(
        self, backend_name: str, entity_uri: str
    ) -> List[Tuple[str, Callable[[Context, Any], Response]]]:
        """
        Expose one or more metadata endpoints required to publish metadata
        information about this handler (for example public keys, configurations,
        policies, etc.). The endpoints are attached to a backend whose name is the
        first function argument.

        The result of this method is a list of elements where each one is of type
        List[Tuple[str, Callable[[Context, Any], Response]]], compliant with
        satosa.backend.BackendModule.register_endpoints:
        1. the first element of the tuple is a regexp used for routing to that endpoint;
        2. the second element is an HTTP handler that can provide a Response given the Context.

        The entity_uri is the full path component of the exposed satosa module and
        may be used as issuer value when signing tokens. Due to satosa routing
        restrictions, exposed endpoints must start with the satosa module name.

        If the TrustHandler has no associated metadata endpoints, return an empty list.
        """

        return []

    def get_handled_trust_material_name(self) -> str:
        """
        Return the name of the trust material that this handler can handle.

        :returns: The name of the trust material
        :rtype: str
        """
        raise NotImplementedError

    def extract_jwt_header_trust_parameters(
        self, trust_source: TrustSourceData
    ) -> dict:
        """
        Parse a trust source to extract the trust parameters (in the source)
        that can be used as a JWT header according to what this very own trust
        evaluation mechanism is capable of understanding.

        Some trust evaluation mechanism is not associated to any JWT header
        mechanism, in which case an empty dictionary is returned.
        """

        return {}

    def validate_trust_material(
        self,
        chain: list[str],
        trust_source: TrustSourceData,
    ) -> tuple[bool, TrustSourceData]:
        """
        Validate the trust chain using the trust handler.

        :param trust_chain: The trust chain to validate
        :type trust_chain: list[str]
        :param trust_source: The trust source
        :type trust_source: TrustSourceData
        :param db_engine: The database engine
        :type db_engine: DBEngine

        :returns: True if the trust chain is valid, False otherwise
        :rtype: bool
        """

        raise NotImplementedError

    def get_client_id(self) -> Optional[str]:
        """
        Return the client ID associated with this trust evaluator.
        This is typically used for OAuth2 or OpenID Connect flows.
        """

        return getattr(self, "client_id", None)

    def is_it_me(self, client_id: str) -> bool:
        """
        Returns true if, according to this trust framework implementation,
        the argument client_id refers to the implementation itself as a
        *member* of the trust framework.
        """

        return client_id == self.get_client_id()

    @property
    def name(self) -> str:
        """
        Return the name of the trust handler.

        :returns: The name of the trust handler
        :rtype: str
        """

        return str(self.__class__.__name__)

    @property
    def default_client_id(self) -> str:
        """
        Return the default client id of the trust handler.

        :returns: The default client id of the trust handler
        :rtype: str
        """

        return self.client_id
