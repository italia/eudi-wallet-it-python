import datetime
import hashlib
import json
import logging
from typing import Any

from pydantic import ValidationError
from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect

from pyeudiw.openid4vp.authorization_response import AuthorizeResponseDirectPost, AuthorizeResponsePayload
from pyeudiw.openid4vp.exceptions import InvalidVPToken, KIDNotFound
from pyeudiw.openid4vp.utils import infer_vp_iss, infer_vp_typ, infer_vp_header_claim
from pyeudiw.openid4vp.vp import SUPPORTED_VC_TYPES, Vp
from pyeudiw.openid4vp.vp_mock import MockVpVerifier
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt
from pyeudiw.openid4vp.vp_sd_jwt_kb import VpVcSdJwtKbVerifier, VpVerifier
from pyeudiw.satosa.exceptions import (AuthorizeUnmatchedResponse, BadRequestError, FinalizedSessionError,
                                       InvalidInternalStateError, NotTrustedFederationError, HTTPError)
from pyeudiw.satosa.interfaces.response_handler import ResponseHandlerInterface
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.satosa.utils.trust import BackendTrust
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.tools.utils import iat_now
from pyeudiw.trust import TrustEvaluationHelper


class ResponseHandler(ResponseHandlerInterface, BackendTrust):
    _SUPPORTED_RESPONSE_METHOD = "post"
    _SUPPORTED_RESPONSE_CONTENT_TYPE = "application/x-www-form-urlencoded"
    _ACCEPTED_ISSUER_METADATA_TYPE = "openid_credential_issuer"

    def _handle_credential_trust(self, context: Context, vp: Vp) -> bool:
        try:
            # establish the trust with the issuer of the credential by checking it to the revocation
            # inspect VP's iss or trust_chain if available or x5c if available
            # TODO: X.509 as alternative to Federation

            # for each single vp token, take the credential within it, use cnf.jwk to validate the vp token signature -> if not exception
            # establish the trust to each credential issuer
            tchelper = self._validate_trust(context, vp.payload['vp'])

            if not tchelper.is_trusted:
                return self._handle_400(context, f"Trust Evaluation failed for {tchelper.entity_id}")

            # TODO: generalyze also for x509
            if isinstance(vp, VpSdJwt):
                credential_jwks = tchelper.get_trusted_jwks(
                    metadata_type='openid_credential_issuer'
                )
                vp.set_credential_jwks(credential_jwks)
        except InvalidVPToken:
            return self._handle_400(context, f"Cannot validate VP: {vp.jwt}")
        except ValidationError as e:
            return self._handle_400(context, f"Error validating schemas: {e}")
        except KIDNotFound as e:
            return self._handle_400(context, f"Kid error: {e}")
        except NotTrustedFederationError as e:
            return self._handle_400(context, f"Not trusted federation error: {e}")
        except Exception as e:
            return self._handle_400(context, f"VP parsing error: {e}")

    def _extract_all_user_attributes(self, attributes_by_issuers: dict) -> dict:
        # for all the valid credentials, take the payload and the disclosure and disclose user attributes
        # returns the user attributes ...
        all_user_attributes = dict()
        for i in attributes_by_issuers.values():
            all_user_attributes.update(**i)
        return all_user_attributes

    def _parse_http_request(self, context: Context) -> dict:
        """Parse the http layer of the request to extract the dictionary data.

        :param context: the satosa context containing, among the others, the details of the HTTP request
        :type context: satosa.Context

        :return: a dictionary containing the request data
        :rtype: dict

        :raises BadRequestError: when request paramets are in a not processable state; the expected handling is returning 400
        """
        if (http_method := context.request_method.lower()) != ResponseHandler._SUPPORTED_RESPONSE_METHOD:
            raise BadRequestError(f"HTTP method [{http_method}] not supported")

        if (content_type := context.http_headers['HTTP_CONTENT_TYPE']) != ResponseHandler._SUPPORTED_RESPONSE_CONTENT_TYPE:
            raise BadRequestError(f"HTTP content type [{content_type}] not supported")

        _endpoint = f"{self.server_url}{context.request_uri}"
        if self.config["metadata"].get('response_uris_supported', None):
            if _endpoint not in self.config["metadata"]['response_uris_supported']:
                raise BadRequestError("response_uri not valid")

        return context.request

    def _detect_typ_iss_vptoken(self, vp_token: str) -> tuple[str, str]:
        typ = infer_vp_typ(vp_token)
        iss = infer_vp_iss(vp_token)
        return typ, iss

    def _retrieve_session_and_nonce_from_state(self, state: str) -> tuple[dict, str]:
        """_retrieve_session_and_nonce_from_state tries to recover an
        authenticasion session by matching it with the state. Returns the whole
        session data (if found) and the nonce proposed in the authentication
        request that should be matched by the holder response.

        :returns: the authentication session information and the nonce challenge
            associated to that authentication request
        :rtype: tuple[dict, str]

        :raises AuthorizeUnmatchedResponse: if the state is not matched to any session
        :raises FinalizedSessionError: if the state is matched to an already closed session
        :raises InvalidInternalStateError: if the session contains invalid, corrupted or missing
            data of known reason.
        """
        request_session: dict = {}
        try:
            request_session = self.db_engine.get_by_state(state=state)
        except Exception as err:
            raise AuthorizeUnmatchedResponse(f"unable to find document-session associated to state {state}", err)

        if not request_session:
            raise InvalidInternalStateError(f"unable to find document-session associated to state {state}")

        if request_session.get("finalized", True):
            raise FinalizedSessionError(f"cannot accept response: session for state {state} corrupted or already finalized")

        nonce = request_session.get("nonce", None)
        if not nonce:
            raise InvalidInternalStateError(f"unnable to find nonce in session associated to state {state}")
        return request_session, nonce

    def _is_same_device_flow(request_session: dict, context: Context) -> bool:
        initiating_session_id: str | None = request_session.get("session_id", None)
        if initiating_session_id is None:
            raise ValueError("invalid session storage information: missing [session_id]")
        current_session_id: str | None = context.state.get("SESSION_ID", None)
        if current_session_id is None:
            raise ValueError("missing session id in wallet authorization response")
        return initiating_session_id == current_session_id

    def response_endpoint(self, context: Context, *args: tuple) -> Redirect | JsonResponse:
        self._log_function_debug("request_endpoint", context, "args", args)

        request_dict = {}
        try:
            request_dict = self._parse_http_request(context)
        except BadRequestError as e:
            return self._handle_400(context, e.args[0], e)

        # parse and decrypt jwt in response
        authz_response: None | AuthorizeResponseDirectPost = None
        authz_payload: None | AuthorizeResponsePayload = None
        try:
            authz_response = AuthorizeResponseDirectPost(**request_dict)
        except Exception as e:
            return self._handle_400(context, "response error: invalid schema or missing jwt", e)
        try:
            authz_payload = authz_response.decode_payload(self.metadata_jwks_by_kids)
        except Exception as e:
            _msg = f"authorization response parsing and/or validation error: {e}"
            self._log_error(context, _msg)
            return self._handle_400(context, _msg, HTTPError(f"error: {e}, with request: {request_dict}"))
        self._log_debug(context, f"response URI endpoint response with payload {authz_payload}")

        request_session, nonce = {}, ""
        try:
            request_session, nonce = self._retrieve_session_and_nonce_from_state(authz_payload.state)
        except AuthorizeUnmatchedResponse as e400:
            self._handle_400(context, e400.args[0], e400.args[1])
        except InvalidInternalStateError as e500:
            self._handle_500(context, e500.args[0], "invalid state")
        except FinalizedSessionError as e400:
            self._handle_400(context, e400.args[0], HTTPError(e400.args[0]))

        # the flow below is a simplified algorithm of authentication response processing, where:
        # (1) we don't check that presentation submission matches definition
        # (2) we don't check that vp tokens are aligned with information declared in the presentation submission
        # (3) we use all disclosed claims in vp tokens to build the user identity
        attributes_by_issuer: dict[str, dict[str, Any]] = {}
        credential_issuers: list[str] = []
        encoded_vps: list[str] = [authz_payload.vp_token] if isinstance(authz_payload.vp_token, str) else authz_payload.vp_token
        for vp_token in encoded_vps:
            # simplified algorithm steps
            # (a): verify that vp is vc+sd-jwt
            # (b): verify that issuer jwt is valid (ok signature, not expired, etc.)
            # (c): verify that binded key is valid (contains nonce above, ok signature, not expired)
            # (d): extract claims for vp in order to build user identity
            try:
                typ, iss = self._detect_typ_iss_vptoken(vp_token)
            except Exception as e:
                return self._handle_400(
                    context,
                    "DirectPostResponse content parse and validation error. Single VPs are faulty.",
                    e
                )
            # self._handle_credential_trust(context, vp)
            credential_issuers.append(iss)
            trust_chain = {"trust_chain": infer_vp_header_claim(vp_token, claim_name="trust_chain")}
            trust_chain_helper = TrustEvaluationHelper(
                self.db_engine,
                httpc_params=self.config['network']['httpc_params'],
                **trust_chain
            )
            issuers_jwks = trust_chain_helper.get_trusted_jwks(ResponseHandler._ACCEPTED_ISSUER_METADATA_TYPE)
            trusted_jwks_by_kid: dict[str, dict] = {jwk["kid"]: jwk for jwk in issuers_jwks}
            if typ not in SUPPORTED_VC_TYPES:
                self._log_warning(context, f"missing or unrecognized typ={typ}; skipping vp token={vp_token}")
                continue
            verifier: VpVerifier | None = None
            match typ:
                case "JWT":
                    verifier = MockVpVerifier(vp_token)
                case "wallet-attestation+jwt":
                    verifier = MockVpVerifier(vp_token)
                case "vc+sd-jwt":
                    verifier = VpVcSdJwtKbVerifier(vp_token, self.client_id, nonce, trusted_jwks_by_kid)
                case "mdoc_cbor":
                    verifier = MockVpVerifier(vp_token)
                case unrecognized_typ:
                    return self._handle_400(context, f"unable to process vp token with typ={unrecognized_typ}")
            if verifier is None:
                return self._handle_500(context, "invalid state", Exception("invalid state"))
            # TODO: revocation check here
            # verifier.check_revocation_status()
            try:
                verifier.verify()
            except InvalidVPToken as e:
                return self._handle_400(context, "invalid vp token", e)
            claims = verifier.parse_digital_credential()
            attributes_by_issuer[iss] = claims
            self._log_debug(context, f"disclosed claims {claims} from issuer {iss}")
        all_attributes = self._extract_all_user_attributes(attributes_by_issuer)
        iss_list_serialized = ";".join(credential_issuers)  # marshaling is whatever
        internal_resp = self._translate_response(all_attributes, iss_list_serialized, context)

        state = authz_payload.state
        response_code = self.response_code_helper.create_code(state)
        try:
            self.db_engine.update_response_object(
                request_session['nonce'], state, internal_resp
            )
            # authentication finalized!
            self.db_engine.set_finalized(request_session['document_id'])
            if self.effective_log_level == logging.DEBUG:
                request_session = self.db_engine.get_by_state(state=state)
                self._log_debug(
                    context, f"Session update on storage: {request_session}")

        except StorageWriteError as e:
            # TODO - do we have to block in the case the update cannot be done?
            self._log_error(context, f"Session update on storage failed: {e}")
            return self._handle_500(context, "Cannot update response object.", e)

        if ResponseHandler._is_same_device_flow(request_session, context):
            # Same device flow
            cb_redirect_uri = f"{self.registered_get_response_endpoint}?response_code={response_code}"
            return JsonResponse({"redirect_uri": cb_redirect_uri}, status="200")
        else:
            # Cross device flow
            return JsonResponse({"status": "OK"}, status="200")

    def _translate_response(self, response: dict, issuer: str, context: Context) -> InternalData:
        """
        Translates wallet response to SATOSA internal response.
        :type response: dict[str, str]
        :type issuer: str
        :type subject_type: str
        :rtype: InternalData
        :param response: Dictioary with attribute name as key.
        :param issuer: The oidc op that gave the repsonse.
        :param subject_type: public or pairwise according to oidc standard.
        :return: A SATOSA internal response.
        """
        # it may depends by credential type and attested security context evaluated
        # if WIA was previously submitted by the Wallet
        timestamp_epoch = (
            response.get("auth_time")
            or response.get("iat")
            or iat_now()
        )
        timestamp_dt = datetime.datetime.fromtimestamp(
            timestamp_epoch,
            datetime.timezone.utc
        )
        timestamp_iso = timestamp_dt.isoformat().replace("+00:00", "Z")

        auth_class_ref = (
            response.get("acr") or
            response.get("amr") or
            self.config["authorization"]["default_acr_value"]
        )
        auth_info = AuthenticationInformation(
            auth_class_ref, timestamp_iso, issuer)

        # TODO - ACR values
        internal_resp = InternalData(auth_info=auth_info)

        # (re)define the response subject
        sub = ""
        pepper = self.config.get("user_attributes", {})[
            'subject_id_random_value'
        ]
        for i in self.config.get("user_attributes", {}).get("unique_identifiers", []):
            if response.get(i):
                _sub = response[i]
                sub = hashlib.sha256(
                    f"{_sub}~{pepper}".encode(
                    )
                ).hexdigest()
                break

        if not sub:
            self._log(
                context,
                level='warning',
                message=(
                    "[USER ATTRIBUTES] Missing subject id from OpenID4VP presentation "
                    "setting a random one for interop for internal frontends"
                )
            )
            sub = hashlib.sha256(
                f"{json.dumps(response).encode()}~{pepper}".encode()
            ).hexdigest()
        response["sub"] = [sub]

        internal_resp.attributes = self.converter.to_internal(
            "openid4vp", response
        )
        internal_resp.subject_id = sub
        return internal_resp
