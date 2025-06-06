import os
import uuid
import copy
import base64
import datetime
import json
import urllib.parse
from unittest.mock import Mock, patch

import pytest
import unittest.mock
from bs4 import BeautifulSoup
from cryptojwt.jws.jws import JWS
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop import DPoPIssuer
from pyeudiw.satosa.backend import OpenID4VPBackend
from pyeudiw.storage.base_storage import TrustType
from pyeudiw.storage.db_engine import DBEngine, TrustType
from pyeudiw.jwt.jws_helper import DEFAULT_SIG_KTY_MAP
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pyeudiw.tests.federation.base import (
    EXP,
    NOW,
    leaf_cred_jwk,
    leaf_wallet_jwk,

    ta_jwk,
    trust_chain_wallet,
    trust_chain_issuer
)
from pyeudiw.tests.settings import (
    BASE_URL,
    CONFIG,
    CREDENTIAL_ISSUER_CONF,
    CREDENTIAL_ISSUER_ENTITY_ID,
    INTERNAL_ATTRIBUTES,
    PRIVATE_JWK,
    WALLET_INSTANCE_ATTESTATION,
    DEFAULT_X509_CHAIN,
    DEFAULT_X509_LEAF_JWK
)
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustEvaluationType
from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt.utils.yaml_specification import yaml_load_specification
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.holder import SDJWTHolder
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.tests.x509.test_x509 import gen_chain
from pyeudiw.x509.verify import PEM_cert_to_B64DER_cert, to_pem_list
from pyeudiw.jwk.parse import parse_pem

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': b"<\xe5\xbc;\x08\xadF\x1d\xc5\x0czR'T&\xbb\x91\xac\x84\xdc\x9ce\xbf\x0b,\x00\xcb\xdd\xbf\xec\xa2\xa5",
    'KID': b"demo-kid"
}

PID_DATA = {
    "eu.europa.ec.eudiw.pid.1": {
        "family_name": "Raffaello",
        "given_name": "Mascetti",
        "birth_date": "1922-03-13",
        "birth_place": "Rome",
        "birth_country": "IT"
    },
    "eu.europa.ec.eudiw.pid.it.1": {
        "tax_id_code": "TINIT-XXXXXXXXXXXXXXX"
    }
}

mdoci = MdocCborIssuer(
    private_key=PKEY,
    alg="ES256",
)

def issue_sd_jwt(specification: dict, settings: dict, issuer_key: JWK, holder_key: JWK, additional_headers: dict) -> dict:
    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": exp_from_now(settings["default_exp"])  # in seconds
    }

    specification.update(claims)
    use_decoys = specification.get("add_decoy_claims", True)

    additional_headers['kid'] = issuer_key["kid"]

    sdjwt_at_issuer = SDJWTIssuer(
        user_claims=specification,
        issuer_keys=[issuer_key],
        holder_key=holder_key,
        add_decoy_claims=use_decoys,
        extra_header_parameters=additional_headers
    )

    return {"jws": sdjwt_at_issuer.serialized_sd_jwt, "issuance": sdjwt_at_issuer.sd_jwt_issuance}

def _mock_auth_callback_function(context: Context, internal_data: InternalData):
    return JsonResponse({"response": "Authentication successful"}, status="200")

class TestOpenID4VPBackend:
    @pytest.fixture(autouse=True)
    def create_backend(self):
        db_engine_inst = DBEngine(CONFIG["storage"])
        
        self.chain = to_pem_list(DEFAULT_X509_CHAIN)
        issuer_pem = self.chain[-1]
        self.x509_leaf_private_key = DEFAULT_X509_LEAF_JWK

        db_engine_inst.add_trust_anchor(
            entity_id="ca.example.com",
            entity_configuration=issuer_pem,
            exp=EXP,
            trust_type=TrustType.X509,
        )

        db_engine_inst.add_trust_anchor(
            entity_id="https://credential-issuer.example.org",
            entity_configuration="-----BEGIN CERTIFICATE-----\nMIIB/jCCAaSgAwIBAgIUUMBi34bUh6gnoMbxypdmBk/JeUMwCgYIKoZIzj0EAwIw\nZDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNh\nbiBGcmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxEzARBgNVBAMMCm15c2l0\nZS5jb20wHhcNMjUwMzI1MTQyMTE0WhcNMjUwNDA0MTQyMTE0WjBkMQswCQYDVQQG\nEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNj\nbzETMBEGA1UECgwKTXkgQ29tcGFueTETMBEGA1UEAwwKbXlzaXRlLmNvbTBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABEXbtJ1tl7OFv1FF4q3BSy7kFlDUxvdQr03c\ncT72OoZw/BR+q735qhltuHSuDeAt5O7yNbSbS0KQbQvf4HQWzDujNDAyMDAGA1Ud\nEQQpMCeGJWh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5vcmcwCgYI\nKoZIzj0EAwIDSAAwRQIgFgMjgF11XRv0E1rtNmWWOarprjbmu6tqOsulAMFXxV4C\nIQDrpFoPCc2uDlEY4BzS10prwAgonpZeg/lm8/ll0IjVkQ==\n-----END CERTIFICATE-----\n",
            exp=EXP,
            trust_type=TrustType.X509,
        )

        self.issuer_jwk = leaf_cred_jwk.serialize(private=True)
        self.holder_jwk = leaf_wallet_jwk.serialize(private=True)

        db_engine_inst.add_or_update_trust_attestation(
            entity_id=CREDENTIAL_ISSUER_ENTITY_ID,
            trust_type=TrustType.DIRECT_TRUST_SD_JWT_VC,
            jwks=[self.issuer_jwk],
        )

        tsd = TrustSourceData.empty(CREDENTIAL_ISSUER_ENTITY_ID)
        tsd.add_trust_param(
            "direct_trust_sd_jwt_vc",
            TrustEvaluationType(
                "jwks",
                jwks=[JWK(key=self.issuer_jwk).as_dict()],
                expiration_date=datetime.datetime.fromtimestamp(exp_from_now(CONFIG["jwt"]["default_exp"])),
                trust_handler_name="DirectTrustSdJwtVc",
            ),
        )

        db_engine_inst.add_trust_source(tsd.serialize())

        self.backend = OpenID4VPBackend(
            Mock(side_effect=_mock_auth_callback_function), 
            INTERNAL_ATTRIBUTES, 
            CONFIG, 
            BASE_URL, 
            "name"
        )

        url_map = self.backend.register_endpoints()
        assert len(url_map) == 7

    @pytest.fixture
    def internal_attributes(self):
        return {
            "attributes": {
                "givenname": {"openid": ["given_name"]},
                "mail": {"openid": ["email"]},
                "edupersontargetedid": {"openid": ["sub"]},
                "surname": {"openid": ["family_name"]},
            }
        }

    @pytest.fixture
    def context(self):
        context = Context()
        context.target_frontend = "someFrontend"
        context.state = State()
        return context
    
    def _generate_payload(self, issuer_jwk, holder_jwk, nonce, state, aud, x509=False):
        settings = CREDENTIAL_ISSUER_CONF
        settings['issuer'] = CREDENTIAL_ISSUER_ENTITY_ID
        settings['default_exp'] = CONFIG['jwt']['default_exp']

        sd_specification = yaml_load_specification(
            settings["sd_specification"])
        
        if x509:
            additional_headers = {
                "x5c": [PEM_cert_to_B64DER_cert(pem) for pem in self.chain]
            }
        else:
            additional_headers = {
                "trust_chain": trust_chain_issuer
            }
        
        issued_jwt = issue_sd_jwt(
            sd_specification,
            settings,
            issuer_jwk,
            holder_jwk,
            additional_headers
        )

        sdjwt_at_holder = SDJWTHolder(
            issued_jwt["issuance"],
            serialization_format="compact",
        )

        sdjwt_at_holder.create_presentation(
            {},
            nonce,
            aud,
            holder_key=holder_jwk,
            sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk["kty"]],
        )

        vp_token = sdjwt_at_holder.sd_jwt_presentation

        mdoci.new(
            doctype="eu.europa.ec.eudiw.pid.1",
            data=PID_DATA,
            validity={
                "issuance_date": "2024-12-31",
                "expiry_date": "2050-12-31"
            }
        )

        vp_token_mdoc = mdoci.dumps().decode()

        return {
            "state": state,
            "vp_token": [vp_token, vp_token_mdoc],
            "presentation_submission": {
                "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
                "descriptor_map": [
                    {
                        "id": "pid-sd-jwt:unique_id+given_name+family_name",
                        "path": "$[0]",
                        "format": "dc+sd-jwt"
                    },
                    {
                        "id": "eu.europa.ec.eudiw.pid.1",
                        "path": "$[1]",
                        "format": "mso_mdoc"
                    }
                ]
            }
        }

    def _initialize_session(self, nonce, state, session_id, remote_flow_typ = "same_device", exp=None):
        self.backend.db_engine.init_session(
            state=state,
            session_id=session_id,
            remote_flow_typ=remote_flow_typ
        )

        doc_id = self.backend.db_engine.get_by_state(state)["document_id"]

        request_object={"nonce": nonce, "state": state}

        if exp:
            request_object["exp"] = exp

        self.backend.db_engine.update_request_object(
            document_id=doc_id,
            request_object=request_object)
    
    def test_backend_init(self):
        assert self.backend.name == "name"

    # TODO: Move to trust evaluation handlers tests
    def test_entity_configuration(self, context):
        context.qs_params = {}

        _fedback: TrustHandlerInterface = self.backend.get_trust_backend_by_class_name(
            "FederationHandler"
        )
        assert _fedback

        entity_config = _fedback.entity_configuration_endpoint(context)
        assert entity_config
        assert entity_config.status == "200"
        assert entity_config.message

        # TODO: decode EC jwt, validate signature and both header and payload schema validation

    def test_pre_request_without_frontend(self):
        context = Context()
        context.state = State()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
        )
        resp = self.backend.pre_request_endpoint(context, InternalData())
        assert resp is not None
        assert resp.status == "400"
        assert resp.message is not None

    def test_pre_request_endpoint(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        assert pre_request_endpoint
        assert pre_request_endpoint.status == "200"
        assert pre_request_endpoint.message

        assert "src='data:image/svg+xml;base64," in pre_request_endpoint.message

        soup = BeautifulSoup(pre_request_endpoint.message, "html.parser")
        # get the img tag with src attribute starting with data:image/svg+xml;base64,
        img_tag = soup.find(
            lambda tag: tag.name == "img"
            and tag.get("src", "").startswith("data:image/svg+xml;base64,")
        )
        assert img_tag
        # get the src attribute
        src = img_tag["src"]
        # remove the data:image/svg+xml;base64, part
        data = src.replace("data:image/svg+xml;base64,", "")
        # decode the base64 data
        base64.b64decode(data).decode("utf-8")

        # get the div with id "state"
        state_div = soup.find("div", {"id": "state"})
        assert state_div
        assert state_div["value"]

    def test_pre_request_endpoint_mobile(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        assert pre_request_endpoint
        assert "302" in pre_request_endpoint.status

        assert (
            f"{CONFIG['authorization']['url_scheme']}://"
            in pre_request_endpoint.message
        )

        unquoted = urllib.parse.unquote(
            pre_request_endpoint.message, encoding="utf-8", errors="replace"
        )
        parsed = urllib.parse.urlparse(unquoted)

        assert parsed.scheme == CONFIG["authorization"]["url_scheme"]
        assert parsed.path == ""
        assert parsed.query

        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["client_id"][0] == CONFIG["metadata"]["client_id"]
        assert qs["request_uri"][0].startswith(CONFIG["metadata"]["request_uris"][0])

    def test_fail_vp_validation_in_response_endpoint(self, context):
        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])
        
        response = self._generate_payload(self.issuer_jwk, self.holder_jwk, nonce, state, self.backend.client_id)

        session_id = context.state["SESSION_ID"]
        # Put a different nonce in the stored request object.
        # This will trigger a `VPInvalidNonce` error
        self._initialize_session(str(uuid.uuid4()), state, session_id)

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        
        context.request = {
            "response": encrypted_response
        }

        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "400"
        msg = json.loads(response_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid presentation submission: validation error"

        # check that malformed jwt result in 400 response
        response["vp_token"][0] = "asd.fgh.jkl"
        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "400"
        msg = json.loads(response_endpoint.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid presentation submission: validation error"

    def test_response_endpoint(self, context):
        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        session_id = context.state["SESSION_ID"]
        self._initialize_session(nonce, state, session_id, exp=exp_from_now(3000))
        
        bad_nonce = str(uuid.uuid4())
        bad_state = str(uuid.uuid4())
        bad_aud = str(uuid.uuid4())

        # case (1): bad nonce
        bad_nonce_response = self._generate_payload(self.issuer_jwk, self.holder_jwk, bad_nonce, state, self.backend.client_id)

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(bad_nonce_response)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status.startswith("4")
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid presentation submission: validation error"

        # case (2): bad state
        bad_state_response = self._generate_payload(self.issuer_jwk, self.holder_jwk, nonce, bad_state, self.backend.client_id)

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(bad_state_response)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status == "400"
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid authorization response: cannot find the session associated to the state"

        # case (3): bad aud
        bad_aud_response = self._generate_payload(self.issuer_jwk, self.holder_jwk, nonce, state, bad_aud)

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(bad_aud_response)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status.startswith("4")
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid presentation submission: validation error"

        # case (4): good aud, nonce and state
        good_response = self._generate_payload(self.issuer_jwk, self.holder_jwk, nonce, state, self.backend.client_id)
        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(good_response)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "200"
        assert "redirect_uri" in response_endpoint.message

        # test status endpoint
        msg = json.loads(response_endpoint.message)

        resp_code = msg['redirect_uri'].split('=')[1]
        session_id = context.state.get("SESSION_ID", None)

        state = self.backend.response_code_helper.recover_state(resp_code)

        assert state is not None

        finalized_session = self.backend.db_engine.get_by_state_and_session_id(
            state=state, session_id=session_id
        )

        assert finalized_session is not None
        assert 'internal_response' in finalized_session
        assert finalized_session['internal_response'] is not None
        assert 'attributes' in finalized_session['internal_response']
        assert finalized_session['internal_response']['attributes'] is not None
        assert 'edupersontargetedid' in finalized_session['internal_response']['attributes']
        assert 'spidcode' in finalized_session['internal_response']['attributes']
        assert len(finalized_session['internal_response']['attributes']['edupersontargetedid']) == 1
        assert len(finalized_session['internal_response']['attributes']['spidcode']) == 1

        context.request_method = "GET"
        context.qs_params = {"response_code": resp_code}

        response = self.backend.get_response_endpoint(context)

        assert response.status == "200"
        assert response.message
        assert "Authentication successful" in response.message

        context.request_method = "GET"
        context.qs_params = {"id": state}
        status_endpoint = self.backend.status_endpoint(context)

        assert status_endpoint.status == "200"
        assert "redirect_uri" in response_endpoint.message

    def test_response_endpoint_no_key_binding_jwt(self, context):
        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        session_id = context.state["SESSION_ID"]
        self._initialize_session(nonce, state, session_id)

        response = self._generate_payload(self.issuer_jwk, self.holder_jwk, None, state, self.backend.client_id)

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status == "400"
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid presentation submission: validation error"
    
    def test_response_endpoint_invalid_signature(self, context):
        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        session_id = context.state["SESSION_ID"]
        self._initialize_session(nonce, state, session_id)

        response = self._generate_payload(self.issuer_jwk, self.holder_jwk, nonce, state, self.backend.client_id)

        jwt_segments = response["vp_token"][0].split(".")

        midlen = len(jwt_segments[2]) // 2
        jwt_segments[2] = jwt_segments[2][:midlen] + jwt_segments[2][midlen+1:] 

        response["vp_token"][0] = ".".join(jwt_segments)

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(response)
        
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        msg = json.loads(response_endpoint.message)

        assert response_endpoint.status == "400"
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid presentation submission: validation error"

    def test_response_endpoint_no_typ_session_must_fail(self, context):
        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        session_id = context.state["SESSION_ID"]
        self._initialize_session(nonce, state, session_id, None)

        response = self._generate_payload(self.issuer_jwk, self.holder_jwk, nonce, state, self.backend.client_id)

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]
        ).encrypt(response)
        context.request = {
            "response": encrypted_response
        }
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "500"
        msg = json.loads(response_endpoint.message)
        assert msg["error"] == "server_error"
        assert msg["error_description"] == "flow error: unable to identify flow from stored session"

    def test_response_endpoint_already_finalized_session_must_fail(self, context):
        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        session_id = context.state["SESSION_ID"]
        self._initialize_session(nonce, state, session_id)

        good_response = self._generate_payload(self.issuer_jwk, self.holder_jwk, nonce, state, self.backend.client_id)

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(good_response)
        context.request = {
            "response": encrypted_response
        }
        context.request_method = "POST"
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}
        
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "200"
        assert "redirect_uri" in response_endpoint.message

        response_endpoint = self.backend.response_endpoint(context)

        msg = json.loads(response_endpoint.message)
        assert response_endpoint.status == "400"
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "invalid authorization response: session already finalized or corrupted"

    def test_response_endpoint_x5c_chain(self, context):

        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        session_id = context.state["SESSION_ID"]
        self._initialize_session(nonce, state, session_id)

        issuer_jwk = parse_pem(self.chain[0])

        good_response = self._generate_payload(self.x509_leaf_private_key, self.holder_jwk, nonce, state, self.backend.client_id, x509=True)

        encrypted_response = JWEHelper(
            CONFIG["metadata_jwks"][1]).encrypt(good_response)
        context.request = {
            "response": encrypted_response
        }
        context.request_method = "POST"
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}
        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "200"
        assert "redirect_uri" in response_endpoint.message

    def test_status_endpoint_no_session(self, context):
        # No query string parameters
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "400"
        assert state_endpoint_response.message
        request_object_jwt = json.loads(state_endpoint_response.message)
        assert request_object_jwt["error"] == "invalid_request"
        assert request_object_jwt["error_description"] == "request error: missing or invalid parameter [id]"

        # Invalid state
        context.qs_params = {"id": None}
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "400"
        assert state_endpoint_response.message
        request_object_jwt = json.loads(state_endpoint_response.message)
        assert request_object_jwt["error"]
        assert request_object_jwt["error"] == "invalid_request"
        assert request_object_jwt["error_description"] == "request error: missing or invalid parameter [id]"

        # Unexistent session
        context.qs_params = {"id": str(uuid.uuid4())}
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "401"
        assert state_endpoint_response.message
        request_object_jwt = json.loads(state_endpoint_response.message)
        assert request_object_jwt["error"] == "invalid_client"
        assert request_object_jwt["error_description"] == "client error: no session associated to the state"

    def test_response_endpoint_error_flow(self, context):
        self.backend.register_endpoints()

        settings = CREDENTIAL_ISSUER_CONF
        settings['issuer'] = CREDENTIAL_ISSUER_ENTITY_ID
        settings['default_exp'] = CONFIG['jwt']['default_exp']

        nonce = str(uuid.uuid4())
        state = str(uuid.uuid4())

        session_id = context.state["SESSION_ID"]
        self.backend.db_engine.init_session(
            state=state,
            session_id=session_id,
            remote_flow_typ="same_device"
        )
        doc_id = self.backend.db_engine.get_by_state(state)["document_id"]

        self.backend.db_engine.update_request_object(
            document_id=doc_id,
            request_object={"nonce": nonce, "state": state})

        context.request_method = "POST"
        context.request_uri = CONFIG["metadata"]["response_uris"][0].removeprefix(
            CONFIG["base_url"])

        response_with_error = {
            "state": state,
            "error": "invalid_request",
            "error_description": "invalid request"
        }

        context.request = response_with_error
        context.http_headers = {"HTTP_CONTENT_TYPE": "application/x-www-form-urlencoded"}

        response_endpoint = self.backend.response_endpoint(context)
        assert response_endpoint.status == "200"

        doc = self.backend.db_engine.get_by_state(state)

        assert doc["finalized"] == True
        assert "error_response" in doc
        assert doc["error_response"] == response_with_error

    def test_request_endpoint(self, context):
        # No session created
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "400"
        assert state_endpoint_response.message
        request_object_jwt = json.loads(state_endpoint_response.message)
        assert request_object_jwt["error"] == "invalid_request"
        assert request_object_jwt["error_description"] == "request error: missing or invalid parameter [id]"

        # Invalid state
        context.qs_params = {"id": None}
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "400"
        assert state_endpoint_response.message
        request_object_jwt = json.loads(state_endpoint_response.message)
        assert request_object_jwt["error"] == "invalid_request"
        assert request_object_jwt["error_description"] == "request error: missing or invalid parameter [id]"

        # Unexistent session
        context.qs_params = {"id": str(uuid.uuid4())}
        state_endpoint_response = self.backend.status_endpoint(context)
        assert state_endpoint_response.status == "401"
        assert state_endpoint_response.message
        request_object_jwt = json.loads(state_endpoint_response.message)
        assert request_object_jwt["error"] == "invalid_client"
        assert request_object_jwt["error_description"] == "client error: no session associated to the state"

    def test_request_endpoint_no_id(self, context):
        context.qs_params = {}
        context.request_method = "GET"
        context.qs_params = {"id": str(uuid.uuid4())}
        request_uri = CONFIG["metadata"]["request_uris"][0]
        context.request_uri = request_uri

        req_resp = self.backend.request_endpoint(context)
        req_resp_str = f"Response(status={req_resp.status}, message={req_resp.message}, headers={req_resp.headers}"
        assert req_resp
        assert req_resp.status == "401", f"invalid status in request object response {req_resp_str}"
        assert req_resp.message, f"invalid message in request object response {req_resp_str}"

        msg = json.loads(req_resp.message)
        assert msg["error"] == "invalid_client"
        assert msg["error_description"] == "session error: cannot find the session associated to the state"

        context.qs_params = {"id": None}
        req_resp = self.backend.request_endpoint(context)

        assert req_resp.status == "400"
        assert req_resp.message
        
        msg = json.loads(req_resp.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "request error: missing or invalid parameter [id]"


        context.qs_params = {}
        req_resp = self.backend.request_endpoint(context)

        assert req_resp.status == "400"
        assert req_resp.message
        
        msg = json.loads(req_resp.message)
        assert msg["error"] == "invalid_request"
        assert msg["error_description"] == "request error: missing or invalid parameter [id]"

    def test_request_endpoint(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        state = urllib.parse.unquote(pre_request_endpoint.message).split("=")[-1]

        jwshelper = JWSHelper(PRIVATE_JWK)

        wia = jwshelper.sign(
            plain_dict=WALLET_INSTANCE_ATTESTATION,
            protected={
                "trust_chain": trust_chain_wallet,
                "x5c": [],
            },
        )

        dpop_wia = wia

        dpop_proof = DPoPIssuer(
            htu=CONFIG["metadata"]["request_uris"][0],
            token=dpop_wia,
            private_jwk=PRIVATE_JWK,
        ).proof

        context.http_headers = dict(
            HTTP_AUTHORIZATION=f"DPoP {dpop_wia}", HTTP_DPOP=dpop_proof
        )

        context.qs_params = {"id": state}

        # put a trust attestation related itself into the storage
        # this then is used as trust_chain header parameter in the signed
        # request object
        db_engine_inst = DBEngine(CONFIG["storage"])

        _fedback: TrustHandlerInterface = self.backend.get_trust_backend_by_class_name(
            "FederationHandler"
        )
        assert _fedback

        _es = {
            "exp": EXP,
            "iat": NOW,
            "iss": "https://trust-anchor.example.org",
            "sub": self.backend.client_id,
            "jwks": _fedback.entity_configuration_as_dict["jwks"],
        }
        ta_signer = JWS(_es, alg="ES256", typ="application/entity-statement+jwt")

        its_trust_chain = [
            _fedback.entity_configuration,
            ta_signer.sign_compact([ta_jwk]),
        ]
        db_engine_inst.add_or_update_trust_attestation(
            entity_id=self.backend.client_id,
            attestation=its_trust_chain,
            exp=datetime.datetime.now().isoformat(),
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
        request_uri = CONFIG["metadata"]["request_uris"][0]
        context.request_uri = request_uri

        req_resp = self.backend.request_endpoint(context)
        req_resp_str = f"Response(status={req_resp.status}, message={req_resp.message}, headers={req_resp.headers})"
        obtained_content_types = list(
            map(
                lambda header_name_value_pair: header_name_value_pair[1],
                filter(
                    lambda header_name_value_pair: header_name_value_pair[0].lower()
                    == "content-type",
                    req_resp.headers,
                ),
            )
        )
        assert req_resp
        assert (
            req_resp.status == "200"
        ), f"invalid status in request object response {req_resp_str}"
        assert (
            len(obtained_content_types) > 0
        ), f"missing Content-Type in request object response {req_resp_str}"
        assert (
            obtained_content_types[0] == "application/oauth-authz-req+jwt"
        ), f"invalid Content-Type in request object response {req_resp_str}"
        assert (
            req_resp.message
        ), f"invalid message in request object response {req_resp_str}"
        request_object_jwt = req_resp.message

        header = decode_jwt_header(request_object_jwt)
        payload = decode_jwt_payload(request_object_jwt)
        assert header["alg"]
        assert header["kid"]
        assert header["typ"] == "oauth-authz-req+jwt"
        assert payload["scope"] == " ".join(CONFIG["authorization"]["scopes"])
        assert payload["client_id"] == CONFIG["metadata"]["client_id"]
        assert (
            payload["response_uri"] == CONFIG["metadata"]["response_uris"][0]
        )

        datetime_mock = Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2999, 1, 1)
        with patch("datetime.datetime", new=datetime_mock):
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

    def test_request_endpoint_post(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        state = urllib.parse.unquote(pre_request_endpoint.message).split("=")[-1]

        jwshelper = JWSHelper(PRIVATE_JWK)

        wia = jwshelper.sign(
            plain_dict=WALLET_INSTANCE_ATTESTATION,
            protected={
                "trust_chain": trust_chain_wallet,
                "x5c": [],
            },
        )

        dpop_wia = wia

        dpop_proof = DPoPIssuer(
            htu=CONFIG["metadata"]["request_uris"][0],
            token=dpop_wia,
            private_jwk=PRIVATE_JWK,
        ).proof

        context.http_headers = dict(
            HTTP_AUTHORIZATION=f"DPoP {dpop_wia}", HTTP_DPOP=dpop_proof
        )

        context.qs_params = {"id": state}

        # put a trust attestation related itself into the storage
        # this then is used as trust_chain header parameter in the signed
        # request object
        db_engine_inst = DBEngine(CONFIG["storage"])

        _fedback: TrustHandlerInterface = self.backend.get_trust_backend_by_class_name(
            "FederationHandler"
        )
        assert _fedback

        _es = {
            "exp": EXP,
            "iat": NOW,
            "iss": "https://trust-anchor.example.org",
            "sub": self.backend.client_id,
            "jwks": _fedback.entity_configuration_as_dict["jwks"],
        }
        ta_signer = JWS(_es, alg="ES256", typ="application/entity-statement+jwt")

        its_trust_chain = [
            _fedback.entity_configuration,
            ta_signer.sign_compact([ta_jwk]),
        ]
        db_engine_inst.add_or_update_trust_attestation(
            entity_id=self.backend.client_id,
            attestation=its_trust_chain,
            exp=datetime.datetime.now().isoformat(),
        )
        # End RP trust chain

        context.request_method = "POST"
        context.request = {
            "wallet_metadata": {
                "vp_formats_supported": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["ES256"],
                        "kb-jwt_alg_values": ["ES256"]
                    }
                }
            },
            "wallet_nonce": "qPmxiNFCR3QTm19POc8u"
        }
        request_uri = CONFIG["metadata"]["request_uris"][0]
        context.request_uri = request_uri

        req_resp = self.backend.request_endpoint(context)
        req_resp_str = f"Response(status={req_resp.status}, message={req_resp.message}, headers={req_resp.headers})"
        obtained_content_types = list(
            map(
                lambda header_name_value_pair: header_name_value_pair[1],
                filter(
                    lambda header_name_value_pair: header_name_value_pair[0].lower()
                    == "content-type",
                    req_resp.headers,
                ),
            )
        )
        assert req_resp
        assert (
            req_resp.status == "200"
        ), f"invalid status in request object response {req_resp_str}"
        assert (
            len(obtained_content_types) > 0
        ), f"missing Content-Type in request object response {req_resp_str}"
        assert (
            obtained_content_types[0] == "application/oauth-authz-req+jwt"
        ), f"invalid Content-Type in request object response {req_resp_str}"
        assert (
            req_resp.message
        ), f"invalid message in request object response {req_resp_str}"
        request_object_jwt = req_resp.message

        header = decode_jwt_header(request_object_jwt)
        payload = decode_jwt_payload(request_object_jwt)
        assert header["alg"]
        assert header["kid"]
        assert header["typ"] == "oauth-authz-req+jwt"
        assert payload["scope"] == " ".join(CONFIG["authorization"]["scopes"])
        assert payload["client_id"] == CONFIG["metadata"]["client_id"]
        assert (
            payload["response_uri"] == CONFIG["metadata"]["response_uris"][0]
        )
        assert payload["wallet_nonce"] == "qPmxiNFCR3QTm19POc8u"

        document = db_engine_inst.get_by_session_id(context.state["SESSION_ID"])

        assert document

        assert document["request_object"]["wallet_metadata"] == {
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            }
        }

        assert document["request_object"]["wallet_nonce"] == "qPmxiNFCR3QTm19POc8u"

    def test_trust_parameters_in_response(self, context):
        internal_data = InternalData()
        context.http_headers = dict(
            HTTP_USER_AGENT="Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"
        )
        pre_request_endpoint = self.backend.pre_request_endpoint(context, internal_data)
        state = urllib.parse.unquote(pre_request_endpoint.message).split("=")[-1]

        context.qs_params = {"id": state}
        context.request_method = "GET"
        context.qs_params = {"id": state}
        request_uri = CONFIG["metadata"]["request_uris"][0]
        context.request_uri = request_uri

        tsd = TrustSourceData.empty(CREDENTIAL_ISSUER_ENTITY_ID)
        tsd.add_trust_param(
            "federation",
            TrustEvaluationType(
                attribute_name="trust_chain",
                jwks=[JWK(key=ta_jwk).as_dict()],
                expiration_date=datetime.datetime.now(),
                trust_chain=trust_chain_wallet,
                trust_handler_name="FederationHandler",
            )
        )

        mocked_jwks_document_endpoint = unittest.mock.patch(
            "pyeudiw.trust.handler.federation.FederationHandler.extract_and_update_trust_materials",
            return_value=tsd,
        )

        mocked_jwks_document_endpoint.start()
        req_resp = self.backend.request_endpoint(context)
        mocked_jwks_document_endpoint.stop()

        assert req_resp
        assert req_resp.status == "200"
        
        header = decode_jwt_header(req_resp.message)

        assert header["trust_chain"]
        assert header["trust_chain"] == trust_chain_wallet
        assert header["x5c"]
        assert len(header["x5c"]) == 3

        # verify that the JWT is signed using the leaf key from the x5c certificate chain
        leaf_key = parse_pem(header["x5c"][0]).as_dict()

        verification = JWSHelper(leaf_key).verify(
            req_resp.message,
        )

        assert verification

    def test_handle_error(self, context):
        error_message = "server_error"
        error_resp = self.backend._handle_500(context, error_message, Exception())
        assert error_resp.status == "500"
        assert error_resp.message
        err = json.loads(error_resp.message)
        assert err["error"] == error_message

    