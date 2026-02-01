"""
Parsing of request_uri from login page HTML (e.g. QR code payload or fallback regex).
"""
import re
import urllib.parse

from bs4 import BeautifulSoup


def _extract_request_uri_from_page_regex(page_content: str) -> str | None:
    """Fallback: extract request_uri from page content via regex when QR element is missing or different."""
    # Match request_uri=... in query strings or in contents="...request_uri=..."
    m = re.search(r"request_uri=([^&\s\"'<>]+)", page_content)
    if m:
        return urllib.parse.unquote(m.group(1).rstrip())
    # JSON/JS style: "request_uri":"..." or 'request_uri':'...'
    m = re.search(r"[\"']request_uri[\"']\s*:\s*[\"']([^\"']+)[\"']", page_content)
    if m:
        return urllib.parse.unquote(m.group(1).rstrip())
    return None


def _request_uri_from_contents_value(contents: str) -> str | None:
    """Parse request_uri from a QR contents string (query string or full URL)."""
    if not contents or not contents.strip():
        return None
    # May be full URL or just query string
    if "request_uri=" in contents:
        parsed = urllib.parse.parse_qs(
            contents if "?" not in contents else contents.split("?", 1)[1]
        )
        if "request_uri" in parsed and parsed["request_uri"]:
            return parsed["request_uri"][0]
    return None


def extract_request_uri_login_page(page_content: str) -> str:
    """
    Parse the QR code in the login page and return the request_uri field
    embedded in the QR code value.
    If the expected element (content-qrcode-payload) is missing, tries a regex
    fallback on the raw page.
    """
    bs = BeautifulSoup(page_content, features="html.parser")
    qrcode_container = bs.find(id="content-qrcode-payload")
    if qrcode_container is not None:
        # Try canonical structure: second child is <qr-code contents="...">
        children = list(qrcode_container.children)
        if len(children) >= 2:
            qrcode_element = children[1]
            if hasattr(qrcode_element, "get") and qrcode_element.get("contents"):
                out = _request_uri_from_contents_value(qrcode_element.get("contents"))
                if out:
                    return out
        # Fallback: any descendant with contents attribute
        for tag in qrcode_container.descendants:
            if hasattr(tag, "get") and tag.get("contents"):
                out = _request_uri_from_contents_value(tag.get("contents"))
                if out:
                    return out
    # Any element in the page with contents= containing request_uri
    for tag in bs.find_all(attrs={"contents": True}):
        out = _request_uri_from_contents_value(tag.get("contents", ""))
        if out:
            return out
    request_uri = _extract_request_uri_from_page_regex(page_content)
    if request_uri:
        return request_uri
    raise ValueError(
        "Could not extract request_uri from login page: no content-qrcode-payload element and no request_uri in page content"
    )
