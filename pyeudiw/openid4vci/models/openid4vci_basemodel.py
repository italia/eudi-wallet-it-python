from typing import Any

from pydantic import BaseModel

from pyeudiw.openid4vci.utils.config import Config

CONFIG_CTX = "config"

class OpenId4VciBaseModel(BaseModel):

    def get_config(self) -> Config:
        return Config(self.get_ctx(CONFIG_CTX))

    def get_ctx(self, path: str) -> Any:
        ctx = self.__pydantic_context__
        if not ctx or path not in ctx:
            raise ValueError(f"Missing '{path}' in pydantic context")
        return ctx[path]