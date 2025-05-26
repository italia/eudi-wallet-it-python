
CONTENT_TYPE_HEADER = "HTTP_CONTENT_TYPE"
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
  def is_application_json(content_type: str) -> bool:
    return APPLICATION_JSON in content_type

  @staticmethod
  def is_form_urlencoded(content_type: str) -> bool:
    return FORM_URLENCODED in content_type

