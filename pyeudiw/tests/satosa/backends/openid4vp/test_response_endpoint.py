import unittest

from idpyoidc.server.user_authn.authn_context import UNSPECIFIED
from satosa.context import Context

from pyeudiw.satosa.backends.openid4vp.endpoints.response_endpoint import ResponseHandler
from pyeudiw.satosa.schemas.autorization import AuthorizationConfig


class TestResponseAuthenticationContext(unittest.TestCase):
    def test_authentication_context_fallback(self):
        cases = [
            ({}, UNSPECIFIED),
            ({"amr": "method"}, "method"),
            ({"acr": "context", "amr": "method"}, "context"),
        ]
        for response, expected in cases:
            with self.subTest(response=response):
                handler = object.__new__(ResponseHandler)
                handler.config = {
                    "user_attributes": {
                        "subject_id_random_value": "test",
                        "unique_identifiers": ["identifier"],
                    },
                }
                handler._converter = None
                result = handler._translate_response(
                    {"identifier": "subject", **response}, "issuer", Context()
                )
                self.assertEqual(result.auth_info.auth_class_ref, expected)

    def test_authorization_config_does_not_require_acr(self):
        config = AuthorizationConfig(
            url_scheme="haip-vp",
            expiration_time=2,
            aud="https://self-issued.me/v2",
            response_mode="direct_post.jwt",
        )
        self.assertNotIn("default_acr_value", config.model_dump())
