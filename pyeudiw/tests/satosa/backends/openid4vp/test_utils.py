import pytest
from satosa.context import Context

from pyeudiw.satosa.backends.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.satosa.backends.openid4vp.utils import detect_flow_typ

_DESKTOP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
]

_SMARTPHONE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Samsung SM-G990B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
]


@pytest.mark.parametrize("useragent", _DESKTOP_USER_AGENTS)
def test_detect_flow_typ_as_cross_device(useragent):
    context = Context()
    context.http_headers = {
        "HTTP_USER_AGENT": useragent,
    }
    assert detect_flow_typ(context) is RemoteFlowType.CROSS_DEVICE


@pytest.mark.parametrize("useragent", _SMARTPHONE_USER_AGENTS)
def test_detect_flow_typ_as_same_device(useragent):
    context = Context()
    context.http_headers = {
        "HTTP_USER_AGENT": useragent,
    }
    assert detect_flow_typ(context) is RemoteFlowType.SAME_DEVICE


@pytest.mark.parametrize("useragent", _SMARTPHONE_USER_AGENTS)
def test_detect_flow_typ_as_same_device_with_accepted_referer(useragent):
    context = Context()
    context.http_headers = {
        "HTTP_USER_AGENT": useragent,
        "HTTP_SEC_FETCH_SITE": "cross-site",
        "HTTP_REFERER": "https://example.wallet.org/",
    }
    assert detect_flow_typ(context, ["https://example.wallet.org/"]) is RemoteFlowType.SAME_DEVICE


@pytest.mark.parametrize("useragent", _SMARTPHONE_USER_AGENTS)
def test_detect_flow_typ_as_same_device_with_invalid_accepted_referer(useragent):
    context = Context()
    context.http_headers = {
        "HTTP_USER_AGENT": useragent,
        "HTTP_SEC_FETCH_SITE": "cross-site",
        "HTTP_REFERER": "https://wrongexample.wallet.org/",
    }
    assert detect_flow_typ(context, ["https://example.wallet.org/"]) is RemoteFlowType.SAME_DEVICE


@pytest.mark.parametrize("useragent", _SMARTPHONE_USER_AGENTS)
def test_detect_flow_typ_as_same_device_regex_match(useragent):
    context = Context()
    context.http_headers = {"HTTP_USER_AGENT": useragent, "HTTP_REFERER": "https://eudi-wallet.example.com/dashboard", "HTTP_SEC_FETCH_SITE": "cross-site"}
    assert detect_flow_typ(context, [r"^https://eudi-wallet\.example\.(it|org|com|eu|dev)"]) is RemoteFlowType.SAME_DEVICE


@pytest.mark.parametrize("useragent", _SMARTPHONE_USER_AGENTS)
def test_detect_flow_typ_as_same_device_regex_no_match(useragent):
    context = Context()
    context.http_headers = {"HTTP_USER_AGENT": useragent, "HTTP_REFERER": "https://untrusted.example.com", "HTTP_SEC_FETCH_SITE": "cross-site"}
    assert detect_flow_typ(context, [r"^https://eudi-wallet\.example\.(it|org|com|eu|dev)"]) is RemoteFlowType.SAME_DEVICE


@pytest.mark.parametrize("useragent", _DESKTOP_USER_AGENTS)
def test_detect_flow_typ_as_same_device_regex_match_desktop(useragent):
    context = Context()
    context.http_headers = {"HTTP_USER_AGENT": useragent, "HTTP_REFERER": "https://eudi-wallet.example.com/dashboard", "HTTP_SEC_FETCH_SITE": "cross-site"}
    assert detect_flow_typ(context, [r"^https://eudi-wallet\.example\.(it|org|com|eu|dev)"]) is RemoteFlowType.SAME_DEVICE


@pytest.mark.parametrize("useragent", _DESKTOP_USER_AGENTS)
def test_detect_flow_typ_as_cross_device_regex_no_match(useragent):
    context = Context()
    context.http_headers = {"HTTP_USER_AGENT": useragent, "HTTP_REFERER": "https://untrusted.example.com", "HTTP_SEC_FETCH_SITE": "cross-site"}
    assert detect_flow_typ(context, [r"^https://eudi-wallet\.example\.(it|org|com|eu|dev)"]) is RemoteFlowType.CROSS_DEVICE
