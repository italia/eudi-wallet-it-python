
CONTENT_TYPE_HEADER = "Content-Type"
APPLICATION_JSON = "application/json"
FORM_URLENCODED = "application/x-www-form-urlencoded"

class ContentTypeUtils:
  """
  Utility class for handling and checking HTTP Content-Type headers.

  This class provides constants for common MIME types (content types),
  and static methods to validate or recognize them from HTTP headers.

  Constants:
      APPLICATION_JSON (str): The MIME type for JSON - "application/json".
      FORM_URLENCODED (str): The MIME type for form URL-encoded data - "application/x-www-form-urlencoded".

  Static Methods:
      is_json(content_type: str) -> bool:
          Returns True if the given content type is exactly "application/json".

      is_xml(content_type: str) -> bool:
          Returns True if the given content type is exactly "application/xml".

      is_text_plain(content_type: str) -> bool:
          Returns True if the given content type is exactly "text/plain".

      is_html(content_type: str) -> bool:
          Returns True if the given content type is exactly "text/html".

      is_form_urlencoded(content_type: str) -> bool:
          Returns True if the given content type is exactly "application/x-www-form-urlencoded".

      is_multipart_form_data(content_type: str) -> bool:
          Returns True if the given content type starts with "multipart/form-data".

  Usage Example:
      >>> ContentTypeUtils.is_application_json("application/json")
      True

      >>> ContentTypeUtils.is_form_urlencoded("multipart/form-data; boundary=xyz")
      False
  """

  @staticmethod
  def _equals(value: str, expected: str) -> bool:
    if not value or not value.strip():
      return False
    return value.strip().lower() == expected

  @staticmethod
  def is_application_json(content_type: str) -> bool:
    return ContentTypeUtils._equals(content_type, APPLICATION_JSON)

  @staticmethod
  def is_form_urlencoded(content_type: str) -> bool:
    return ContentTypeUtils._equals(content_type, FORM_URLENCODED)

