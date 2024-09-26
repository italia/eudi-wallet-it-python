import importlib

from jwcrypto.jwk import JWK

from pyeudiw.trust.default.direct_trust import DirectTrustSdJwtVc
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.trust._log import _package_logger


class TrustEvaluator:
    """
    TrustEvaluator is an interface that defined the expected behaviour of a
    class that, as the very core, can:
    (1) obtain the cryptographic material of an issuer, which might or might
        not be trusted according to some trust model
    (2) obtain the meta information about an issuer that is defined
        according to some trust model
    """

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

    def is_revoked(self, issuer: str) -> bool:
        """
        yield if the trust toward the issuer was revoked according to some trust model;
        this asusmed that  the isser exists, is valid, but is not trusted.
        """
        raise NotImplementedError

    def get_policies(self, issuer: str) -> dict:
        raise NotImplementedError("reserved for future uses")


DEFAULT_HTTPC_PARAMS = {
    "connection": {
        "ssl": True
    },
    "session": {
        "timeout": 6
    }
}


class IssuerTrustEvaluator:

    def __init__(self, trust_config: dict):
        self.trust_configs: dict = trust_config
        self.trust_methods: dict[str, object] = {}
        if not self.trust_configs:
            _package_logger.warning("no configured trust model, using direct trust model")
            self.trust_methods["direct_trust"] = DirectTrustSdJwtVc(DEFAULT_HTTPC_PARAMS)
            return
        for k, v in self.trust_configs.items():
            try:
                module = importlib.import_module(v["module"])
                class_type = getattr(module, v["class"])
                class_config = v["config"]
            except KeyError as e:
                _package_logger.critical(f"invalid trust configuration for {k}: missing mandatory fields [module] and/or [class]")
                raise TrustConfigurationError(f"invalid configuration for {k}: {e}", e)
            except Exception as e:
                raise TrustConfigurationError(f"invalid config: {e}", e)
            _package_logger.debug(f"loading {class_type} with config {class_config}")
            self.trust_methods[k] = class_type(**class_config)

    def get_public_keys(self, issuer: str) -> list[dict]:
        """
        yields the public cryptographic material of the issuer

        :returns: a list of jwk(s)
        """
        raise NotImplementedError

    def get_metadata(self, issuer: str) -> dict:
        raise NotImplementedError

    def is_revoked(self, issuer: str) -> bool:
        raise NotImplementedError

    def get_policies(self, issuer: str) -> dict:
        raise NotImplementedError("reserved for future uses")

    def get_verified_key(self, issuer: str, token_header: dict) -> JWK:  # ← TODO: consider removal
        raise NotImplementedError
