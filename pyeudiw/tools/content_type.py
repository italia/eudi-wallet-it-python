HTTP_CONTENT_TYPE_HEADER = "HTTP_CONTENT_TYPE"
CONTENT_TYPE_HEADER = "content-type"
CACHE_CONTROL_HEADER = "Cache-Control"
APPLICATION_JSON = "application/json"
FORM_URLENCODED = "application/x-www-form-urlencoded"

def is_application_json(content_type: str) -> bool:
  """
  Check if the provided Content-Type header indicates JSON content.

  Args:
      content_type (str): The value of the Content-Type header.

  Returns:
      bool: True if the content type includes "application/json", False otherwise.
  """
  return APPLICATION_JSON in content_type


def is_form_urlencoded(content_type: str) -> bool:
  """
  Check if the provided Content-Type header indicates form-urlencoded content.

  Args:
      content_type (str): The value of the Content-Type header.

  Returns:
      bool: True if the content type includes "application/x-www-form-urlencoded", False otherwise.
  """
  return FORM_URLENCODED in content_type


def get_content_type_header(headers: list[tuple[str, str]]) -> str | None:
  """
  Retrieve the Content-Type header value from a list of HTTP headers.

  Args:
      headers (list[tuple[str, str]]): A list of header key-value pairs.

  Returns:
      str | None: The value of the Content-Type header if present, None otherwise.
  """
  return next((v for k, v in headers if k.lower() == CONTENT_TYPE_HEADER), None)
