from pyeudiw.tools.content_type import (
    is_application_json,
    is_form_urlencoded,
    get_content_type_header
)

def test_is_application_json():
    assert is_application_json("application/json")
    assert is_application_json("application/json; charset=utf-8")
    assert not is_application_json("text/plain")

def test_is_form_urlencoded():
    assert is_form_urlencoded("application/x-www-form-urlencoded")
    assert not is_form_urlencoded("multipart/form-data")

def test_get_content_type_header_present():
    headers_present = [
        ("X-Test", "value"),
        ("Content-Type", "application/json"),
        ("Another-Header", "xyz")
    ]
    assert get_content_type_header(headers_present) == "application/json"

    headers_case_insensitive = [
        ("content-TYPE", "application/json")
    ]
    assert get_content_type_header(headers_case_insensitive) == "application/json"

    headers_not_found = [
        ("X-Test", "value"),
        ("Accept", "application/json")
    ]
    assert get_content_type_header(headers_not_found) is None

