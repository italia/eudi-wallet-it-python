HTTP_CONTENT_TYPE_HEADER = "HTTP_CONTENT_TYPE"
CONTENT_TYPE_HEADER = "content-type"
CACHE_CONTROL_HEADER = "Cache-Control"
APPLICATION_JSON = "application/json"
FORM_URLENCODED = "application/x-www-form-urlencoded"

def is_application_json(content_type: str) -> bool:
  return APPLICATION_JSON in content_type

def is_form_urlencoded(content_type: str) -> bool:
  return FORM_URLENCODED in content_type

def get_content_type_header(headers: list[tuple[str, str]]) -> str | None:
  return next((v for k, v in headers if k.lower() == CONTENT_TYPE_HEADER), None)
