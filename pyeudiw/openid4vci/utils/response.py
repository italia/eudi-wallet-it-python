import json
from urllib.parse import urlencode

from satosa.response import BadRequest, Unauthorized, Redirect, ServiceError

from pyeudiw.openid4vci.utils.content_type import APPLICATION_JSON, \
    FORM_URLENCODED


class ResponseUtils:

  @staticmethod
  def to_invalid_scope_resp(desc: str) -> BadRequest:
    return BadRequest(
        json.dumps({"error": "invalid_scope", "error_description": desc}),
        content = APPLICATION_JSON
    )

  @staticmethod
  def to_invalid_request_resp(desc: str) -> BadRequest:
    return BadRequest(
        json.dumps({"error": "invalid_request", "error_description": desc}),
        content = APPLICATION_JSON
    )

  @staticmethod
  def to_invalid_client_resp(desc: str) -> Unauthorized:
    return Unauthorized(
        json.dumps({"error": "invalid_client", "error_description": desc}),
        content = APPLICATION_JSON
    )

  @staticmethod
  def to_server_error_resp(desc: str) -> ServiceError:
    return ServiceError(
        json.dumps({"error": "server_error", "error_description": desc}),
        content = APPLICATION_JSON
    )

  @staticmethod
  def to_invalid_request_redirect(url: str, desc: str, state:str) -> Redirect:
    params = ResponseUtils._error_redirect("invalid_request", desc, state)
    return Redirect(
        f"{url}?{urlencode(params)}",
        content = FORM_URLENCODED
    )

  @staticmethod
  def to_server_error_redirect(url: str, desc: str, state:str | None = None) -> Redirect:
    params = ResponseUtils._error_redirect("server_error", desc, state)
    return Redirect(
        f"{url}?{urlencode(params)}",
        content = FORM_URLENCODED
    )

  @staticmethod
  def _error_redirect(error:str, desc: str, state: str):
      params = {
          "error": error,
          "error_description": desc
      }
      if state is not None:
          params["state"] = state
      return params