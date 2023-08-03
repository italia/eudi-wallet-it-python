import base64
import tempfile

from pyeudiw.tools.qr_code import QRCode


def test_to_base64():
    data = "content"
    size = 5
    color = "black"

    qr = QRCode(data, size, color)
    b64 = qr.to_base64()
    assert isinstance(b64, str)
    assert len(b64) > 0
    assert base64.b64decode(b64.encode()).decode('utf-8') == qr.to_svg()


def test_to_html():
    data = "content"
    size = 5
    color = "black"

    qr = QRCode(data, size, color)
    html = qr.to_html()
    assert isinstance(html, str)
    assert len(html) > 0
    assert html.startswith("<img")
    assert html.endswith(">")
    assert "data:image/svg+xml;base64," in html
    b64 = html.split("data:image/svg+xml;base64,")[1].split('"')[0]
    assert base64.b64decode(b64.encode()).decode('utf-8') == qr.to_svg()


def test_to_svg():
    data = "content"
    size = 5
    color = "black"

    qr = QRCode(data, size, color)
    svg = qr.to_svg()

    assert isinstance(svg, str)
    assert len(svg) > 0
    assert svg.strip().startswith("<?xml")
    assert "<svg" in svg
    assert svg.strip().endswith("</svg>")


# Set to `False` to keep files for manual inspection
DELETE_FILES = True


def _test_to_html_file():
    data = "content"
    size = 5
    color = "black"

    qr = QRCode(data, size, color)
    html = qr.to_html()
    with tempfile.NamedTemporaryFile("w", suffix=".html", dir=".", delete=DELETE_FILES) as tmp:
        tmp.writelines(html)


def _test_to_svg_file():
    data = "content"
    size = 5
    color = "black"

    qr = QRCode(data, size, color)
    svg = qr.to_svg()
    with tempfile.NamedTemporaryFile("w", suffix=".svg", dir=".", delete=DELETE_FILES) as tmp:
        tmp.writelines(svg)
