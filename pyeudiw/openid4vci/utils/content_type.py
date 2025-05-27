HTTP_CONTENT_TYPE_HEADER = "HTTP_CONTENT_TYPE"
CONTENT_TYPE_HEADER = "content-type"
CACHE_CONTROL_HEADER = "Cache-Control"
APPLICATION_JSON = "application/json"
FORM_URLENCODED = "application/x-www-form-urlencoded"

class ContentTypeUtils:
  """
  Utility class for handling and checking HTTP Content-Type headers.

  This class provides constants for common MIME types (content types),
  and static methods to validate or recognize them from HTTP headers.

  Usage Examples:
      >>> ContentTypeUtils.is_application_json("application/json; charset=utf-8")
      True

      >>> ContentTypeUtils.get_content_type_header([
      ...     ("Content-Type", "application/json"),
      ...     ("X-Custom", "value")
      ... ])
      'application/json'
  """

  @staticmethod
  def is_application_json(content_type: str) -> bool:
    return APPLICATION_JSON in content_type

  @staticmethod
  def is_form_urlencoded(content_type: str) -> bool:
    return FORM_URLENCODED in content_type

  @staticmethod
  def get_content_type_header(headers: list[tuple[str, str]]) -> str | None:
    return next((v for k, v in headers if k.lower() == CONTENT_TYPE_HEADER), None)
