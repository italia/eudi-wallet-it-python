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
    'error_page': '/<name>/error',

    'wallet_relay_party': {
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
