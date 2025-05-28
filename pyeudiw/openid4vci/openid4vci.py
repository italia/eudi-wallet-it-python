"""
The OpenID4vci (Credential Issuer) frontend module for the satosa proxy
"""
import logging
from typing import Callable

from satosa.context import Context
from satosa.frontends.base import FrontendModule
from satosa.internal import InternalData
from satosa.response import Response

from pyeudiw.openid4vci.endpoints import Openid4VCIEndpoints
from pyeudiw.openid4vci.utils.config import Config

logger = logging.getLogger(__name__)

class OpenID4VCIFrontend(FrontendModule, Openid4VCIEndpoints):
  """
  OpenID Connect frontend module based on satosa.
  """

  def __init__(self,
               auth_req_callback_func: Callable[[Context, InternalData], Response],
       internal_attributes: dict[str, dict[str, str | list[str]]],
       config: dict[str, dict[str, str] | list[str]],
       base_url: str,
       name: str,
  ):
    FrontendModule.__init__(self, auth_req_callback_func, internal_attributes, base_url, name)
    Openid4VCIEndpoints.__init__(self, config, base_url, name)
    self.config = config
    self.config_utils = Config(**config)

  def register_endpoints(self, *kwargs):
    """
    See super class satosa.frontends.base.FrontendModule
    :type backend_names: list[str]
    :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
    :raise ValueError: if more than one backend is configured
    """
    url_map = []
    endpoint_values = [v for k, v in vars(self.config_utils.get_oauth_authorization_server()).items() if k.endswith("endpoint")]
    for method, path in endpoint_values:
      url_map.append((f"{self.name}/{path}", getattr(self, f"{method}")))

    logger.debug(f"Loaded Credential Issuer endpoints: {url_map}")
    return url_map