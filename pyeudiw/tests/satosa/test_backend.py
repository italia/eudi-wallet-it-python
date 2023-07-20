import base64
import json
import urllib.parse
from unittest.mock import Mock

import pytest

from pyeudiw.satosa.backend import OpenID4VPBackend

BASE_URL = "https://example.com"
AUTHZ_PAGE = "example.com"
AUTH_ENDPOINT = "https://example.com/auth"
CLIENT_ID = "client_id"

CONFIG = {
    'server_info': {
        'authorization_endpoint': AUTH_ENDPOINT,
        'token_endpoint': "https://example.com/auth/oauth/access_token"
    },
    'client_secret': 'facebook_secret',
    'base_url': BASE_URL,
    'state_encryption_key': 'state_encryption_key',
    'encryption_key': 'encryption_key',
    'fields': ['id', 'name', 'first_name', 'last_name', 'middle_name', 'picture', 'email',
               'verified', 'gender', 'timezone', 'locale', 'updated_time'],
    'authz_page': AUTHZ_PAGE,
    'client_config': {'client_id': CLIENT_ID},

    'pre_request_endpoint': '/<name>/show_qrcode',
    'redirect_endpoint': '/<name>/redirect_uri',
    'request_endpoint': '/<name>/request_uri',
    'entity_configuration_endpoint': '/<name>/entity_configuration',
    'error_url': '/<name>/error',

    'wallet_relying_party': {
        'client_id': 'client_id',
        'redirect_uris': ['https://example.com/redirect_uri'],
        'request_uris': ['https://example.com/request_uri'],
    },

    'qr_code_settings': {
        'size': 100,
        'color': '#2B4375',
        'logo_path': '<logo-path>',
        'use_zlib': True,
    }
}

RESPONSE_CODE = "CODE"

INTERNAL_ATTRIBUTES: dict = {
    'attributes': {}
}


class TestOpenID4VPBackend:
    @pytest.fixture(autouse=True)
    def create_backend(self):
        self.backend = OpenID4VPBackend(
            Mock(), INTERNAL_ATTRIBUTES, CONFIG, BASE_URL, "name")

    def test_backend_init(self):
        assert self.backend.name == "name"
        assert self.backend.entity_configuration_url == CONFIG['entity_configuration_endpoint']
        assert self.backend.qr_settings['size'] == CONFIG['qr_code_settings']['size']

    def test_register_endpoints(self):
        url_map = self.backend.register_endpoints()
        assert len(url_map) == 4
        print(url_map)
        assert url_map[0][0] == '^' + \
            CONFIG['entity_configuration_endpoint'].lstrip('/') + '$'
        assert url_map[1][0] == '^' + \
            CONFIG['pre_request_endpoint'].lstrip('/') + '$'
        assert url_map[2][0] == '^' + \
            CONFIG['redirect_endpoint'].lstrip('/') + '$'
        assert url_map[3][0] == '^' + \
            CONFIG['request_endpoint'].lstrip('/') + '$'

    def test_entity_configuration(self):
        entity_config = self.backend.entity_configuration(None)
        assert entity_config
        assert entity_config.status == "200 OK"
        assert entity_config.message

    def test_pre_request_endpoint(self):
        pre_request_endpoint = self.backend.pre_request_endpoint(None)
        assert pre_request_endpoint
        assert pre_request_endpoint.status == "200 OK"
        assert pre_request_endpoint.message

        decoded = base64.b64decode(pre_request_endpoint.message).decode("utf-8")
        assert decoded.startswith("eudiw://authorize?")

        unquoted = urllib.parse.unquote(decoded, encoding='utf-8', errors='replace')
        parsed = urllib.parse.urlparse(unquoted)

        assert parsed.scheme == "eudiw"
        assert parsed.netloc == "authorize"
        assert parsed.path == ""
        assert parsed.query

        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["client_id"][0] == CONFIG["wallet_relying_party"]["client_id"]
        assert qs["request_uri"][0] == CONFIG["wallet_relying_party"]["request_uris"][0]

    def test_redirect_endpoint(self):
        redirect_endpoint = self.backend.redirect_endpoint(None)
        assert redirect_endpoint
        assert redirect_endpoint.status == "200 OK"
        assert redirect_endpoint.message

        msg = json.loads(redirect_endpoint.message)
        assert msg["request"]

    def test_request_endpoint(self):
        request_endpoint = self.backend.request_endpoint(None)
        assert request_endpoint
        assert request_endpoint.status == "200 OK"
        assert request_endpoint.message

        msg = json.loads(request_endpoint.message)
        assert msg["response"]

    def test_handle_error(self):
        error_message = "Error message!"
        error_resp = self.backend.handle_error(error_message)
        assert error_resp.status == "403 Forbidden"
        assert error_resp.message
        err = json.loads(error_resp.message)
        assert err["message"] == error_message
