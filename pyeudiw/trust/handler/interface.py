from typing import Any, Callable

import satosa.context
import satosa.response

from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.storage.db_engine import DBEngine


class TrustHandlerInterface:
    def __init__(self, *args, **kwargs):
        pass

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
    ) -> list[
        tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]
    ]:
        """
        Expose one or more metadata endpoint required to publish metadata
        information about *myself* and that are associated to a trust
        mechanism, such as public keys, configurations, policies, etc.

        The endpoint are attached to a backend whose name is equal to
        the first function argument.

        The result of this method is a list of element where each one is of type
        ```
            tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]
        ```
        compliant to satosa.backend.BackendModule method register_endpoints, that is:
        1. the first argument is a regxp used for rotuing to that endpoint; while \
            not required, due to satosa inernal routing restrictions, the regexp \
            first path must match the backend.
        2. the second argument is an http handler that can provide a response given \
            the information in the context.

        The entity_uri is the full path component of the exposed satosa module.
        In some context, this also matched the entity id of the module and can be
        used as issuer value when signing tokens.
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

        However, due to satosa restrictions, the exposed endpoint MUST start with
        the satosa module name.

        The TrustHandler might not have any associated metadata endpoint, in which case
        an empty list is returned instead.
        """
        return []
    
    def get_handled_trust_material_name(self) -> str:
        """
        Return the name of the trust material that this handler can handle.

        :returns: The name of the trust material
        :rtype: str
        """
        raise NotImplementedError
    
    def extract_jwt_header_trust_parameters(self, trust_source: TrustSourceData) -> dict:
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
            trust_chain: list[str], 
            trust_source: TrustSourceData,
            db_engine: DBEngine
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

    def is_it_me(self, client_id: str) -> bool:
        """
        Returns true if, according to this trust framework implementation,
        the argument client_id refers to the implementation itself as a
        *member* of the trust framework.
        """
        return client_id == self.client_id

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
