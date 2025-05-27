import logging
from typing import Any

from pydantic import BaseModel

from pyeudiw.openid4vci.exceptions.bad_request_exception import InvalidRequestException
from pyeudiw.openid4vci.utils.config import Config

CONFIG_CTX = "config"
CLIENT_ID_CTX = "client_id"
ENDPOINT_CTX = "endpoint"
AUTHORIZATION_DETAILS_CTX = "authorization_details"
ENTITY_ID_CTX = "entity_id"
NONCE_CTX = "nonce"

logger = logging.getLogger(__name__)

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

    @staticmethod
    def check_missing_parameter(parameter: Any, parameter_name: str, endpoint_name: str):
        if not parameter or (isinstance(parameter, list) and len(parameter) == 0):
            logger.error(f"missing {parameter_name} in request `{endpoint_name}` endpoint")
            raise InvalidRequestException(f"missing `{parameter_name}` parameter")

    @staticmethod
    def check_unexpected_parameter(parameter: Any, parameter_name: str, endpoint_name: str):
        if parameter or (isinstance(parameter, list) and len(parameter) > 0):
            logger.error(f"unexpected {parameter_name} in request `{endpoint_name}` endpoint")
            raise InvalidRequestException(f"unexpected `{parameter_name}` parameter")

    @staticmethod
    def check_invalid_parameter(check: bool, parameter: Any, parameter_name: str, endpoint_name: str):
        if check:
            logger.error(f"invalid {parameter_name}" + (f" ({parameter})" if parameter is not None else "") + f" in request `{endpoint_name}` endpoint")
            raise InvalidRequestException(f"invalid `{parameter_name}` parameter")

    @staticmethod
    def strip(val: str):
        return val.strip() if val is not None else val
