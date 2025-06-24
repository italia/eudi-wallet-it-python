HTTP_CONTENT_TYPE_HEADER = "HTTP_CONTENT_TYPE"
CONTENT_TYPE_HEADER = "content-type"
ACCEPT_HEADER = "accept"
CACHE_CONTROL_HEADER = "Cache-Control"
APPLICATION_JSON = "application/json"
FORM_URLENCODED = "application/x-www-form-urlencoded"
ENTITY_STATEMENT_JWT = "application/entity-statement+jwt"
STATUS_LIST_CWT = "application/statuslist+cwt"
STATUS_LIST_JWT = "application/statuslist+jwt"

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
  return _get_header(headers, CONTENT_TYPE_HEADER)

def get_accept_header(headers: list[tuple[str, str]]) -> str | None:
  """
  Retrieve the Accept header value from a list of HTTP headers.

  Args:
      headers (list[tuple[str, str]]): A list of header key-value pairs.

  Returns:
      str | None: The value of the Accept header if present, None otherwise.
  """
  return _get_header(headers, ACCEPT_HEADER)

def _get_header(headers, key):
  """
  Retrieve the value of a header from a collection of headers.

  This function supports both dictionaries and lists of (key, value) pairs.
  Keys are matched case-insensitively.

  :param headers: The headers collection. Can be a dictionary or a list of 2-element tuples/lists.
  :type headers: dict or list[tuple[str, str]]

  :param key: The header name to search for.
  :type key: str

  :return: The value associated with the given header key, or None if not found.
  :rtype: str or None
  """
  if isinstance(headers, dict):
    return headers.get(key) or headers.get(key.lower())
  elif isinstance(headers, list):
    return next(
      (v for h in headers if isinstance(h, (tuple, list)) and len(h) == 2
       for k, v in [h] if k.lower() == key.lower()),
      None
    )
  return None

