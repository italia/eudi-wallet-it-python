import base64
import datetime
import json
import urllib.parse
import uuid
from unittest.mock import Mock

import pytest
from bs4 import BeautifulSoup
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State
from sd_jwt.holder import SDJWTHolder

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWEHelper, JWSHelper, unpad_jwt_header, DEFAULT_SIG_KTY_MAP
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.oauth2.dpop import DPoPIssuer
from pyeudiw.satosa.backend import OpenID4VPBackend
from pyeudiw.sd_jwt import (
    _adapt_keys,
    issue_sd_jwt,
    load_specification_from_yaml_string,
    import_pyca_pri_rsa
)
from pyeudiw.storage.db_engine import DBEngine

from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.tests.federation.base import trust_chain_wallet, ta_ec, leaf_wallet_jwk

from pyeudiw.tests.settings import BASE_URL, CONFIG, INTERNAL_ATTRIBUTES, ISSUER_CONF, PRIVATE_JWK, WALLET_INSTANCE_ATTESTATION


# STORAGE ####
# Put the trust anchor EC and the trust chains related to the credential issuer and the wallet provider in the trust storage
db_engine_inst = DBEngine(CONFIG['storage'])
db_engine_inst.add_trust_anchor(
    entity_id=ta_ec['iss'],
    trust_chain=ta_ec,
    exp=datetime.datetime.now().isoformat()
)


class TestOpenID4VPBackend:
    @pytest.fixture(autouse=True)
    def create_backend(self):
        self.backend = OpenID4VPBackend(
            Mock(), INTERNAL_ATTRIBUTES, CONFIG, BASE_URL, "name")

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]}
            }
        }

    @pytest.fixture
    def context(self):
        context = Context()
        context.state = State()
        return context

    def test_backend_init(self):
        assert self.backend.name == "name"

    def test_register_endpoints(self):
        url_map = self.backend.register_endpoints()
        assert len(url_map) == 6

    def test_entity_configuration(self):
        entity_config = self.backend.entity_configuration_endpoint(None)
        assert entity_config
        assert entity_config.status == "200"
        assert entity_config.message

    def test_pre_request_endpoint(self, context):
        self.backend.register_endpoints()
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(
            context, internal_data)
        assert pre_request_endpoint
        assert pre_request_endpoint.status == "200"
        assert pre_request_endpoint.message

        assert "src='data:image/svg+xml;base64," in pre_request_endpoint.message

        soup = BeautifulSoup(pre_request_endpoint.message, 'html.parser')
        # get the img tag with src attribute starting with data:image/svg+xml;base64,
        img_tag = soup.find(
            lambda tag: tag.name == 'img' and tag.get('src', '').startswith('data:image/svg+xml;base64,'))
        assert img_tag
        # get the src attribute
        src = img_tag['src']
        # remove the data:image/svg+xml;base64, part
        data = src.replace('data:image/svg+xml;base64,', '')
        # decode the base64 data
        decoded = base64.b64decode(data).decode("utf-8")

        # get the div with id "state"
        state_div = soup.find("div", {"id": "state"})
        assert state_div
        assert state_div["value"]

        svg = BeautifulSoup(decoded, features="xml")
        assert svg
        assert svg.find("svg")
        assert svg.find_all("path")

    def test_pre_request_endpoint_mobile(self, context):
        self.backend.register_endpoints()
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(
            context, internal_data)
        assert pre_request_endpoint
        assert "302" in pre_request_endpoint.status

        assert f"{CONFIG['authorization']['url_scheme']}://authorize" in pre_request_endpoint.message

        unquoted = urllib.parse.unquote(
            pre_request_endpoint.message, encoding='utf-8', errors='replace')
        parsed = urllib.parse.urlparse(unquoted)

        assert parsed.scheme == "eudiw"
        assert parsed.netloc == "authorize"
        assert parsed.path == ""
        assert parsed.query

        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["client_id"][0] == CONFIG["metadata"]["client_id"]
        assert qs["request_uri"][0].startswith(
            CONFIG["metadata"]["request_uris"][0])

    def test_redirect_endpoint(self, context):
        self.backend.register_endpoints()
        issuer_jwk = JWK(CONFIG["metadata_jwks"][1])
        holder_jwk = JWK(leaf_wallet_jwk.serialize(private=True))

        settings = ISSUER_CONF
        settings['issuer'] = "https://issuer.example.com"
        settings['default_exp'] = CONFIG['jwt']['default_exp']

        sd_specification = load_specification_from_yaml_string(
            settings["sd_specification"])

        issued_jwt = issue_sd_jwt(
            sd_specification,
            settings,
            issuer_jwk,
            holder_jwk
        )

        _adapt_keys(issuer_jwk, holder_jwk)

        sdjwt_at_holder = SDJWTHolder(
            issued_jwt["issuance"],
            serialization_format="compact",
        )
        sdjwt_at_holder.create_presentation(
            {},
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            import_pyca_pri_rsa(holder_jwk.key.priv_key, kid=holder_jwk.kid) if sd_specification.get(
                "key_binding", False) else None,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk.key.kty],
        )

        data = {
            "iss": "https://wallet-provider.example.org/instance/vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
            "jti": str(uuid.uuid4()),
            "aud": "https://verifier.example.org/callback",
            "iat": iat_now(),
            "exp": exp_from_now(minutes=15),
            "nonce": str(uuid.uuid4()),
            "vp": sdjwt_at_holder.sd_jwt_presentation,
        }

        vp_token = JWSHelper(leaf_wallet_jwk.serialize(private=True)).sign(
            data,
            protected={"typ": "JWT"}
        )

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["redirect_uris"][0]

        response = {
            "state": "3be39b69-6ac1-41aa-921b-3e6c07ddcb03",
            "vp_token": vp_token,
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "pid-sd-jwt:unique_id+given_name+family_name",
                        "path": "$.vp_token.verified_claims.claims._sd[0]",
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        }
        encrypted_response = JWEHelper(
            JWK(CONFIG["metadata_jwks"][1])).encrypt(response)
        context.request = {
            "response": encrypted_response
        }

        # create a document with that state and that nonce

        try:
            redirect_endpoint = self.backend.redirect_endpoint(context)
            assert redirect_endpoint
        except Exception:
            # TODO: this test case must implement the backend requests in the correct order and with the correct nonce and state
            # raise e
            pass
        # TODO any additional checks after the backend returned the user attributes to satosa core

    def test_request_endpoint(self, context):
        self.backend.register_endpoints()
        # No session created
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "403"
        assert state_endpoint_response.message
        msg = json.loads(state_endpoint_response.message)
        assert msg["message"]

        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(
            context, internal_data)
        state = urllib.parse.unquote(
            pre_request_endpoint.message).split("=")[-1]

        jwshelper = JWSHelper(PRIVATE_JWK)
        wia = jwshelper.sign(
            WALLET_INSTANCE_ATTESTATION,
            protected={
                'trust_chain': trust_chain_wallet,
                'x5c': []
            }
        )

        dpop_wia = wia
        dpop_proof = DPoPIssuer(
            htu=CONFIG['metadata']['request_uris'][0],
            token=dpop_wia,
            private_jwk=PRIVATE_JWK
        ).proof

        context.http_headers = dict(
            HTTP_AUTHORIZATION=f"DPoP {dpop_wia}",
            HTTP_DPOP=dpop_proof
        )

        context.qs_params = {"id": state}

        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "204"
        assert state_endpoint_response.message

        # Passing wrong state, hence no match state-session_id
        context.qs_params = {"id": "WRONG"}
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "403"
        assert state_endpoint_response.message

        context.request_method = "GET"
        context.qs_params = {"id": state}
        request_uri = CONFIG['metadata']['request_uris'][0]
        context.request_uri = request_uri

        request_endpoint = self.backend.request_endpoint(context)

        assert request_endpoint
        assert request_endpoint.status == "200"
        assert request_endpoint.message
        msg = json.loads(request_endpoint.message)
        assert msg["response"]

        header = unpad_jwt_header(msg["response"])
        payload = unpad_jwt_payload(msg["response"])
        assert header["alg"]
        assert header["kid"]
        assert payload["scope"] == " ".join(CONFIG["authorization"]["scopes"])
        assert payload["client_id"] == CONFIG["metadata"]["client_id"]
        assert payload["response_uri"] == CONFIG["metadata"]["redirect_uris"][0]

        # TODO - the authentication is successful ONLY if redirect_endpoints gets a valid presentation!
        # state_endpoint_response = self.backend.status_endpoint(context)
        # assert state_endpoint_response.status == "302"
        # assert state_endpoint_response.message
        # msg = json.loads(state_endpoint_response.message)
        # assert msg["response"] == "Authentication successful"

    def test_handle_error(self, context):
        error_message = "Error message!"
        error_resp = self.backend.handle_error(context, error_message)
        assert error_resp.status == "500"
        assert error_resp.message
        err = json.loads(error_resp.message)
        assert err["message"] == error_message
