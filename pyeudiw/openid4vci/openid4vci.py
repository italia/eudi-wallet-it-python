"""
The OpenID4vci (Credential Issuer) frontend module for the satosa proxy
"""
import logging
from typing import Callable

from satosa.context import Context
from satosa.frontends.base import FrontendModule
from satosa.internal import InternalData
from satosa.response import Response

from pyeudiw.openid4vci.storage.openid4vci_engine import OpenId4VciEngine
from pyeudiw.tools.endpoints_loader import EndpointsLoader
from pyeudiw.tools.session import get_session_id

logger = logging.getLogger(__name__)

class OpenID4VCIFrontend(FrontendModule):
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
    self.internal_attributes = internal_attributes
    self.config = config
    self.base_url = base_url
    self.name = name
    self.db_engine = OpenId4VciEngine.db_engine

  def register_endpoints(self, *kwargs):
    """
    See super class satosa.frontends.base.FrontendModule
    :type backend_names: list[str]
    :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
    :raise ValueError: if more than one backend is configured
    """
    el = EndpointsLoader(self.config, self.internal_attributes, self.base_url, self.name)
    url_map = []
    for path, inst in el.endpoint_instances.items():
      url_map.append((f"{self.name}/{path}", inst))

    logger.debug(f"Loaded OpenID4VCI endpoints: {url_map}")
    return url_map

  def handle_authn_response(self, context: Context, internal_resp: InternalData) -> None:
    self.db_engine.update_attributes_by_session_id(get_session_id(context), internal_resp.attributes)
