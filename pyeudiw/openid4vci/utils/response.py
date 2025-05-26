import json

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
    return Redirect(
        f"{url}?error=invalid_request&error_description={desc}&state={state}",
        content = FORM_URLENCODED
    )

  @staticmethod
  def to_server_error_redirect(url: str, desc: str, state:str) -> Redirect:
    return Redirect(
        f"{url}?error=server_error&&error_description={desc}&state={state}",
        content = FORM_URLENCODED
    )