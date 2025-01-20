from typing import Any, Callable
import satosa.context
import satosa.response


class TrustEvaluator:
    """
    TrustEvaluator is an interface that defined the expected behaviour of a
    class that, as the very core, can:
    (1) obtain the cryptographic material of an issuer, which might or might
        not be trusted according to some trust model
    (2) obtain the meta information about an issuer that is defined
        according to some trust model
    """
    def initialize_istance(self, issuer: str) -> None:
        """
        Initialize the cryptographic material of the issuer, according to some
        trust model.
        """
        raise NotImplementedError

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        yields the public cryptographic material of the issuer

        :returns: a list of jwk(s); note that those key are _not_ necessarely
            identified by a kid claim
        """
        raise NotImplementedError

    def get_metadata(self, issuer: str) -> dict:
        """
        yields a dictionary of metadata about an issuer, according to some
        trust model.
        """
        raise NotImplementedError

    def build_metadata_endpoints(self, base_path: str) -> list[tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]:
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

        The base_path is the base path component of the exposed satosa module.
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

    def is_revoked(self, issuer: str) -> bool:
        """
        yield if the trust toward the issuer was revoked according to some trust model;
        this asusmed that  the isser exists, is valid, but is not trusted.
        """
        raise NotImplementedError

    def get_policies(self, issuer: str) -> dict:
        raise NotImplementedError("reserved for future uses")
    
    def get_selfissued_jwt_header_trust_parameters(self) -> dict:
        raise NotImplementedError
