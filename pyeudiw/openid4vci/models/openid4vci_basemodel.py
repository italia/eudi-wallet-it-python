from typing import Any

from pydantic import BaseModel

from pyeudiw.openid4vci.utils.config import Config

CONFIG_CTX = "config"

class OpenId4VciBaseModel(BaseModel):
    """
    Base model that extracts the Pydantic context and provides helper accessors.
    """
    _context: dict[str, Any] = {}

    def model_post_init(self, context: Any) -> None:
        if isinstance(context, dict):
            self._context = context
        else:
            self._context = {}

    def get_config(self) -> Config:
        config_obj = self.get_ctx(CONFIG_CTX)
        if isinstance(config_obj, Config):
            return config_obj
        return Config(**config_obj)

    def get_ctx(self, path: str) -> Any:
        if not self._context or path not in self._context:
            raise ValueError(f"Missing '{path}' in pydantic context")
        return self._context[path]
