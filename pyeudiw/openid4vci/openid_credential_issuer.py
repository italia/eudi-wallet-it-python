from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

import openid4v.openid_credential_issuer
from cryptojwt import KeyJar
from idpyoidc.server import ASConfiguration
from idpyoidc.server.util import execute


class OpenidCredentialIssuer(openid4v.openid_credential_issuer.OpenidCredentialIssuer):

    def __init__(
            self,
            config: Optional[Union[dict, ASConfiguration]] = None,
            upstream_get: Optional[Callable] = None,
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Any] = None,
            httpc_params: Optional[dict] = None,
            entity_id: Optional[str] = "",
            entity_type: Optional[str] = "",
            key_conf: Optional[dict] = None,
            **kwargs
    ):
        openid4v.openid_credential_issuer.OpenidCredentialIssuer.__init__(
            self,
            config=config,
            upstream_get=upstream_get,
            keyjar=keyjar,
            cwd=cwd,
            cookie_handler=cookie_handler,
            httpc=httpc,
            httpc_params=httpc_params,
            entity_id=entity_id,
            key_conf=key_conf,
            entity_type=entity_type
            )

        persistence_conf = config.get("persistence")
        if not persistence_conf:
            raise ValueError("Missing persistence configuration")
        _storage_conf = persistence_conf["kwargs"].get("storage", {})
        if not _storage_conf:
            raise ValueError("Missing persistence storage configuration")
        _storage = execute(_storage_conf)
        persistence_conf["kwargs"]["storage"] = _storage
        persistence_conf["kwargs"]["upstream_get"] = self.unit_get
        self.persistence = execute(persistence_conf)