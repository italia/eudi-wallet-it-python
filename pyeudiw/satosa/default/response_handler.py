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
from pyeudiw.openid4vp.direct_post_response import DirectPostResponse
from pyeudiw.openid4vp.exceptions import (InvalidVPToken, KIDNotFound,
                                          NoNonceInVPToken, VPInvalidNonce,
                                          VPNotFound)
from pyeudiw.openid4vp.schemas.response import ResponseSchema
from pyeudiw.openid4vp.utils import infer_vp_iss, infer_vp_typ
from pyeudiw.openid4vp.vp import SUPPORTED_VC_TYPES, Vp
from pyeudiw.openid4vp.vp_mock import MockVpVerifier
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt
from pyeudiw.openid4vp.vp_sd_jwt_kb import VpVcSdJwtKbVerifier, VpVerifier
from pyeudiw.satosa.exceptions import NotTrustedFederationError, HTTPError
from pyeudiw.satosa.interfaces.response_handler import ResponseHandlerInterface
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.satosa.utils.trust import BackendTrust
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.tools.utils import iat_now
from pyeudiw.trust import TrustEvaluationHelper


# _CallbackErrorHandler_T = Callable[[], JsonResponse]


class ResponseHandler(ResponseHandlerInterface, BackendTrust):
    _SUPPORTED_RESPONSE_METHOD = "post"
    _SUPPORTED_RESPONSE_CONTENT_TYPE = "application/x-www-form-urlencoded"

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

    def _parse_http_request(self, context: Context) -> tuple[dict, JsonResponse | None]:
        """TODO: docs
        """
        if (http_method := context.request_method.lower()) != ResponseHandler._SUPPORTED_RESPONSE_METHOD:
            return "", self._handle_400(context, f"HTTP method [{http_method}] not supported")

        if (content_type := context.http_headers['HTTP_CONTENT_TYPE']) != ResponseHandler._SUPPORTED_RESPONSE_CONTENT_TYPE:
            return "", self._handle_400(context, f"HTTP content type [{content_type}] not supported")

        _endpoint = f'{self.server_url}{context.request_uri}'
        if self.config["metadata"].get('response_uris_supported', None):
            if _endpoint not in self.config["metadata"]['response_uris_supported']:
                return "", self._handle_400(context, "response_uri not valid")

        return context.request, None
        # jwt = context.request.get("response", None)
        # if not jwt:
        #     _msg = "response error: missing JWT"
        #     self._log_error(context, _msg)
        #     return "", self._handle_400(context, _msg)

        # return jwt, None

    def _retrieve_session_and_nonce_from_state(self, context: Context, state: str) -> tuple[dict, str, JsonResponse | None]:
        """TODO: docs
        """
        request_session: dict = {}
        try:
            request_session = self.db_engine.get_by_state(state=state)
        except Exception as err:
            _msg = f"unable to find document-session associated to state {state}"
            return {}, "", self._handle_400(context, _msg, err)

        if request_session.get("finalized", True):
            _msg = f"cannot accept response: session for state {state} corrupted or already finalized"
            return {}, "", self._handle_400(context, _msg, HTTPError(_msg))

        nonce = request_session.get("nonce", None)
        if nonce is None:
            _msg = f"unnable to find nonce in session associated to state {state}"
            return {}, "", self._handle_500(context, _msg, HTTPError(_msg))
        return request_session, nonce, None

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

        # --- START HERE ---
        request_dict, error_response = self._parse_http_request(context)
        if error_response is not None:
            return error_response

        # parse and decrypt jwt in response
        authz_response: None | AuthorizeResponseDirectPost = None
        authz_payload: None | AuthorizeResponsePayload = None
        try:
            authz_response = AuthorizeResponseDirectPost(**request_dict)
        except ValueError as e:
            return self._handle_400(context, "response error: invalid schema or missing jwt", e)
        try:
            authz_payload = authz_response.decode_payload(self.metadata_jwks_by_kids)
        except Exception as e:
            _msg = f"authorization response parsing and/or validation error: {e}"
            self._log_error(context, _msg)
            return self._handle_400(context, _msg, HTTPError(f"error: {e}, with request: {request_dict}"))
        self._log_debug(context, f"response URI endpoint response with payload {authz_payload}")

        request_session, nonce, error_response = self._retrieve_session_and_nonce_from_state(context, authz_payload.state)
        if error_response is not None:
            return error_response

        # the flow below is a simplified algorithm of authentication response processing, where:
        # (1) we don't check that presentation submission matches definition
        # (2) we don't check that vp tokens are aligned with information declared in the presentation submission
        # (3) we use all disclosed claims in vp tokens to build the user identity
        attributes_by_issuer: dict[str, dict[str, Any]] = {}
        credential_issuers: list[str] = []
        encoded_vps: list[str] = [authz_payload.vp_token] if isinstance(authz_payload.vp_token, str) else authz_payload.vp_token
        for vp_token in encoded_vps:
            # self._handle_credential_trust(context, vp)
            typ = infer_vp_typ(vp_token)
            iss = infer_vp_iss(vp_token)
            credential_issuers.append(iss)
            trust_chain_helper = TrustEvaluationHelper(
                self.db_engine,
                httpc_params=self.config['network']['httpc_params']
            )
            issuers_jwks = trust_chain_helper.get_trusted_jwks("openid_credential_issuer")  # TODO: questo puzza
            trusted_jwks_by_kid: dict[str, dict] = {jwk["kid"]: jwk for jwk in issuers_jwks}
            if typ not in SUPPORTED_VC_TYPES:
                self._log_warning(f"missing or unrecognized typ={typ}; skipping vp token={vp_token}")
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
            # verifier.check_revocation_status()
            try:
                verifier.verify()
            except InvalidVPToken as e:
                return self._handle_400(context, "invalid vp token", e)
            claims = verifier.parse_digital_credential()
            attributes_by_issuer[iss] = claims
            self._log_debug(context, f"disclosed claims {claims} from issuer {iss}")
            # TODO:
            # (a): verify that vp is vc+sd-jwt
            # (b): verify that issuer jwt is valid (ok signature, not expired)
            # (c): verify that binded key is valid (contains nonce above, ok signature, not expired)
            # (d): extract claims for vp in order to build user identity
            pass
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

        if self._is_same_device_flow(request_session, context):
            # Same device flow
            cb_redirect_uri = f"{self.registered_get_response_endpoint}?response_code={response_code}"
            return JsonResponse({"redirect_uri": cb_redirect_uri}, status="200")
        else:
            # Cross device flow
            return JsonResponse({"status": "OK"}, status="200")

        # --- END HERE ---

        if context.request_method.lower() != 'post':
            return self._handle_400(context, "HTTP Method not supported")
        _endpoint = f'{self.server_url}{context.request_uri}'
        if self.config["metadata"].get('response_uris_supported', None):
            if _endpoint not in self.config["metadata"]['response_uris_supported']:
                return self._handle_400(context, "response_uri not valid")

        # take the encrypted jwt, decrypt with my public key (one of the metadata) -> if not -> exception
        jwt = context.request.get("response", None)
        if not jwt:
            _msg = "Response error, missing JWT"
            self._log_error(context, _msg)
            return self._handle_400(context, _msg)

        try:
            vpt = DirectPostResponse(jwt, self.metadata_jwks_by_kids)
            debug_message = f"Redirect uri endpoint Response using direct post contains: {vpt.payload}"
            self._log_debug(context, debug_message)
            ResponseSchema(**vpt.payload)
        except Exception as e:
            _msg = f"DirectPostResponse parse and validation error: {e}"
            self._log_error(context, _msg)
            return self._handle_400(context, _msg, HTTPError(f"Error:{e}, with JWT: {jwt}"))

        # state MUST be present in the response since it was in the request
        # then do lookup on the db -> if not -> exception
        state = vpt.payload.get("state", None)
        if not state:
            return self._handle_400(context, _msg, HTTPError(f"{_msg} with: {vpt.payload}"))

        try:
            stored_session = self.db_engine.get_by_state(state=state)
        except Exception as e:
            _msg = "Session lookup by state value failed"
            return self._handle_400(context, _msg, e)

        if stored_session["finalized"]:
            _msg = "Session already finalized"
            return self._handle_400(context, _msg, HTTPError(_msg))

        try:
            vpt.load_nonce(stored_session['nonce'])
            vps: list[Vp] = vpt.get_presentation_vps()
            vpt.validate()

        except VPNotFound as e:
            _msg = "Error while retrieving VP. Payload 'vp_token' is empty or has an unexpected value."
            return self._handle_400(context, _msg, e)

        except NoNonceInVPToken as e:
            _msg = "Error while validating VP: vp has no nonce."
            return self._handle_400(context, _msg, e)

        except VPInvalidNonce as e:
            _msg = "Error while validating VP: unexpected value."
            return self._handle_400(context, _msg, e)

        except Exception as e:
            _msg = (
                "DirectPostResponse content parse and validation error. "
                "Single VPs are faulty."
            )
            return self._handle_400(context, _msg, e)

        # evaluate the trust to each credential issuer found in the vps
        # look for trust chain or x509 or do discovery!
        cred_issuers = tuple(vpt.credentials_by_issuer.keys())
        attributes_by_issuers = {k: {} for k in cred_issuers}

        for vp in vps:
            self._handle_credential_trust(context, vp)

            # the trust is established to the credential issuer, then we can get the disclosed user attributes

            try:
                if isinstance(vp, VpSdJwt):
                    jwks_by_kid = {
                        i['kid']: i for i in vp.credential_jwks
                    }
                    vp.verify(issuer_jwks_by_kid=jwks_by_kid)
                else:
                    vp.verify()
            except Exception as e:
                return self._handle_400(context, f"VP validation error with {self.data}: {e}")

            # vp.result
            attributes_by_issuers[vp.credential_issuer] = vp.disclosed_user_attributes

            debug_message = f"Disclosed user attributes from {vp.credential_issuer}: {vp.disclosed_user_attributes}"
            self._log_debug(context, debug_message)

            vp.check_revocation()

        all_user_attributes = self._extract_all_user_attributes(
            attributes_by_issuers)

        self._log_debug(context, f"Wallet disclosure: {all_user_attributes}")

        # TODO: not sure that we want these issuers in the following form ... please recheck.
        _info = {"issuer": ';'.join(cred_issuers)}
        internal_resp = self._translate_response(
            all_user_attributes, _info["issuer"], context
        )
        response_code = self.response_code_helper.create_code(state)

        try:
            self.db_engine.update_response_object(
                stored_session['nonce'], state, internal_resp
            )
            # authentication finalized!
            self.db_engine.set_finalized(stored_session['document_id'])
            if self.effective_log_level == logging.DEBUG:
                stored_session = self.db_engine.get_by_state(state=state)
                self._log_debug(
                    context, f"Session update on storage: {stored_session}")

        except StorageWriteError as e:
            # TODO - do we have to block in the case the update cannot be done?
            self._log_error(context, f"Session update on storage failed: {e}")
            return self._handle_500(context, "Cannot update response object.", e)

        if stored_session['session_id'] == context.state["SESSION_ID"]:
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
