import base64
import datetime
import json
import urllib.parse
import uuid
from unittest.mock import Mock, patch

import pytest
from bs4 import BeautifulSoup
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State
from sd_jwt.holder import SDJWTHolder

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWEHelper, JWSHelper, decode_jwt_header, DEFAULT_SIG_KTY_MAP
from cryptojwt.jws.jws import JWS
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.oauth2.dpop import DPoPIssuer
from pyeudiw.satosa.backend import OpenID4VPBackend
from pyeudiw.sd_jwt import (
    _adapt_keys,
    issue_sd_jwt,
    load_specification_from_yaml_string,
    import_ec
)
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.tests.federation.base import (
    trust_chain_wallet,
    trust_chain_issuer,
    ta_ec,
    leaf_wallet_jwk,
    EXP,
    NOW,
    ta_jwk,
    ta_ec_signed, leaf_cred_jwk_prot
)
from pyeudiw.tests.settings import (
    BASE_URL,
    CONFIG,
    INTERNAL_ATTRIBUTES,
    ISSUER_CONF,
    PRIVATE_JWK,
    WALLET_INSTANCE_ATTESTATION
)


class TestOpenID4VPBackend:

    @pytest.fixture(autouse=True)
    def create_backend(self):

        db_engine_inst = DBEngine(CONFIG['storage'])
        db_engine_inst.add_trust_anchor(
            entity_id=ta_ec['iss'],
            entity_configuration=ta_ec_signed,
            exp=EXP,
        )

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

    def test_entity_configuration(self, context):
        context.qs_params = {}
        entity_config = self.backend.entity_configuration_endpoint(context)
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

    def test_vp_validation_in_redirect_endpoint(self, context):
        self.backend.register_endpoints()

        issuer_jwk = JWK(leaf_cred_jwk_prot.serialize(private=True))
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
            holder_jwk,
            trust_chain=trust_chain_issuer
        )

        _adapt_keys(issuer_jwk, holder_jwk)

        sdjwt_at_holder = SDJWTHolder(
            issued_jwt["issuance"],
            serialization_format="compact",
        )

        nonce = str(uuid.uuid4())
        sdjwt_at_holder.create_presentation(
            {},
            nonce,
            str(uuid.uuid4()),
            import_ec(holder_jwk.key.priv_key, kid=holder_jwk.kid) if sd_specification.get(
                "key_binding", False) else None,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk.key.kty],
        )

        data = {
            "iss": "https://wallet-provider.example.org/instance/vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
            "jti": str(uuid.uuid4()),
            "aud": "https://verifier.example.org/callback",
            "iat": iat_now(),
            "exp": exp_from_now(minutes=15),
            "nonce": nonce,
            "vp": sdjwt_at_holder.sd_jwt_presentation,
        }

        vp_token = JWSHelper(leaf_wallet_jwk.serialize(private=True)).sign(
            data,
            protected={"typ": "JWT"}
        )

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["redirect_uris"][0].removeprefix(CONFIG["base_url"])

        state = str(uuid.uuid4())
        response = {
            "nonce": nonce,
            "state": state,
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
        session_id = context.state["SESSION_ID"]
        self.backend.db_engine.init_session(
            state=state,
            session_id=session_id
        )
        doc_id = self.backend.db_engine.get_by_state(state)["document_id"]

        # Put a different nonce in the stored request object.
        # This will trigger a `VPInvalidNonce` error
        self.backend.db_engine.update_request_object(
            document_id=doc_id,
            request_object={"nonce": str(uuid.uuid4()), "state": state})

        encrypted_response = JWEHelper(
            JWK(CONFIG["metadata_jwks"][1])).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        request_endpoint = self.backend.request_endpoint(context)
        assert request_endpoint.status == "400"
        msg = json.loads(request_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "Error while validating VP: unexpected value."

        # Recreate data without nonce
        # This will trigger a `NoNonceInVPToken` error
        data = {
            "iss": "https://wallet-provider.example.org/instance/vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
            "jti": str(uuid.uuid4()),
            "aud": "https://verifier.example.org/callback",
            "iat": iat_now(),
            "exp": exp_from_now(minutes=15),
            "vp": sdjwt_at_holder.sd_jwt_presentation,
        }

        vp_token = JWSHelper(leaf_wallet_jwk.serialize(private=True)).sign(
            data,
            protected={"typ": "JWT"}
        )
        response = {
            "nonce": nonce,
            "state": state,
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
        request_endpoint = self.backend.request_endpoint(context)
        assert request_endpoint.status == "400"
        msg = json.loads(request_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "Error while validating VP: vp has no nonce."

        # This will trigger a `UnicodeDecodeError` which will be caught by the generic `Exception case`.
        response["vp_token"] = "asd.fgh.jkl"
        encrypted_response = JWEHelper(
            JWK(CONFIG["metadata_jwks"][1])).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        request_endpoint = self.backend.request_endpoint(context)
        assert request_endpoint.status == "400"
        msg = json.loads(request_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "DirectPostResponse content parse and validation error. Single VPs are faulty."


    def test_redirect_endpoint(self, context):
        self.backend.register_endpoints()

        issuer_jwk = JWK(leaf_cred_jwk_prot.serialize(private=True))
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
            holder_jwk,
            trust_chain=trust_chain_issuer
        )

        _adapt_keys(issuer_jwk, holder_jwk)

        sdjwt_at_holder = SDJWTHolder(
            issued_jwt["issuance"],
            serialization_format="compact",
        )

        nonce = str(uuid.uuid4())
        sdjwt_at_holder.create_presentation(
            {},
            nonce,
            str(uuid.uuid4()),
            import_ec(holder_jwk.key.priv_key, kid=holder_jwk.kid) if sd_specification.get(
                "key_binding", False) else None,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk.key.kty],
        )

        data = {
            "iss": "https://wallet-provider.example.org/instance/vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
            "jti": str(uuid.uuid4()),
            "aud": "https://verifier.example.org/callback",
            "iat": iat_now(),
            "exp": exp_from_now(minutes=15),
            "nonce": nonce,
            "vp": sdjwt_at_holder.sd_jwt_presentation,
        }

        vp_token = JWSHelper(leaf_wallet_jwk.serialize(private=True)).sign(
            data,
            protected={"typ": "JWT"}
        )

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["redirect_uris"][0].removeprefix(CONFIG["base_url"])

        state = str(uuid.uuid4())
        response = {
            "state": state,
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

        # no nonce
        request_endpoint = self.backend.request_endpoint(context)
        msg = json.loads(request_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert "nonce" in msg["error_description"]
        assert "missing" in msg["error_description"]

        # wrong nonce
        response["nonce"] = str(uuid.uuid4())
        encrypted_response = JWEHelper(
            JWK(CONFIG["metadata_jwks"][1])).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        request_endpoint = self.backend.request_endpoint(context)
        msg = json.loads(request_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "Session lookup by state value failed"

        # correct nonce but not the state
        response["nonce"] = nonce
        encrypted_response = JWEHelper(
            JWK(CONFIG["metadata_jwks"][1])).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        request_endpoint = self.backend.request_endpoint(context)
        msg = json.loads(request_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "Session lookup by state value failed"

        session_id = context.state["SESSION_ID"]
        self.backend.db_engine.init_session(
            state=state,
            session_id=session_id
        )
        doc_id = self.backend.db_engine.get_by_state(state)["document_id"]

        self.backend.db_engine.update_request_object(
            document_id=doc_id,
            request_object={"nonce": nonce, "state": state})
        request_endpoint = self.backend.request_endpoint(context)
        assert request_endpoint.status == "302 Found"


    def test_request_endpoint(self, context):
        self.backend.register_endpoints()
        # No session created
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "400"
        assert state_endpoint_response.message
        msg = json.loads(state_endpoint_response.message)
        assert msg["error"]

        internal_data = InternalData()
        context.http_headers = dict(
           HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(
            context, internal_data
        )
        state = urllib.parse.unquote(
            pre_request_endpoint.message).split("=")[-1]

        jwshelper = JWSHelper(PRIVATE_JWK)
        wia = jwshelper.sign(
            WALLET_INSTANCE_ATTESTATION,
            protected={
                'trust_chain': trust_chain_wallet,
                'x5c': [],
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

        # put a trust attestation related itself into the storage
        # this then is used as trust_chain header paramenter in the signed
        # request object
        db_engine_inst = DBEngine(CONFIG['storage'])

        _es = ta_es = {
            "exp": EXP,
            "iat": NOW,
            "iss": "https://trust-anchor.example.org",
            "sub": self.backend.client_id,
            'jwks': self.backend.entity_configuration_as_dict['jwks']
        }
        ta_signer = JWS(_es, alg="ES256",
                        typ="application/entity-statement+jwt")

        its_trust_chain = [
            self.backend.entity_configuration,
            ta_signer.sign_compact([ta_jwk])
        ]
        db_engine_inst.add_or_update_trust_attestation(
            entity_id=self.backend.client_id,
            attestation=its_trust_chain,
            exp=datetime.datetime.now().isoformat()
        )
        # End RP trust chain

        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "201"
        assert state_endpoint_response.message

        # Passing wrong state, hence no match state-session_id
        context.qs_params = {"id": "WRONG"}
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "401"
        assert state_endpoint_response.message

        context.request_method = "GET"
        context.qs_params = {"id": state}
        request_uri = CONFIG['metadata']['request_uris'][0]
        context.request_uri = request_uri

        response_endpoint = self.backend.response_endpoint(context)

        assert response_endpoint
        assert response_endpoint.status == "200"
        assert response_endpoint.message
        msg = json.loads(response_endpoint.message)
        assert msg["response"]

        header = decode_jwt_header(msg["response"])
        payload = decode_jwt_payload(msg["response"])
        assert header["alg"]
        assert header["kid"]
        assert payload["scope"] == " ".join(CONFIG["authorization"]["scopes"])
        assert payload["client_id"] == CONFIG["metadata"]["client_id"]
        assert payload["response_uri"] == CONFIG["metadata"]["redirect_uris"][0]

        datetime_mock = Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2999, 1, 1)
        with patch('datetime.datetime', new=datetime_mock):
            self.backend.status_endpoint(context)
            state_endpoint_response = self.backend.status_endpoint(context)
            assert state_endpoint_response.status == "403"
            assert state_endpoint_response.message
            err = json.loads(state_endpoint_response.message)
            assert err["error"] == "expired"

        # TODO - the authentication is successful ONLY if redirect_endpoints gets a valid presentation!
        # state_endpoint_response = self.backend.status_endpoint(context)
        # assert state_endpoint_response.status == "302"
        # assert state_endpoint_response.message
        # msg = json.loads(state_endpoint_response.message)
        # assert msg["response"] == "Authentication successful"

    def test_handle_error(self, context):
        error_message = "server_error"
        error_resp = self.backend._handle_500(context, error_message, Exception())
        assert error_resp.status == "500"
        assert error_resp.message
        err = json.loads(error_resp.message)
        assert err["error"] == error_message
