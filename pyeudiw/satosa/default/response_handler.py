import datetime
import hashlib
import json
import logging

from copy import deepcopy
from dataclasses import asdict
from typing import Any, Union

from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect

from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.openid4vp.authorization_response import (
    AuthorizeResponsePayload,
    DirectPostJwtJweParser,
    DirectPostParser,
    detect_response_mode,
)
from pyeudiw.openid4vp.schemas.response import ErrorResponsePayload
from pyeudiw.openid4vp.exceptions import (
    AuthRespParsingException,
    AuthRespValidationException,
)
from pyeudiw.openid4vp.interface import VpTokenParser, VpTokenVerifier
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.openid4vp.schemas.response import ResponseMode
from pyeudiw.openid4vp.vp_sd_jwt_vc import VpVcSdJwtParserVerifier
from pyeudiw.satosa.exceptions import (
    AuthorizeUnmatchedResponse,
    FinalizedSessionError,
    InvalidInternalStateError,
)
from pyeudiw.satosa.interfaces.response_handler import ResponseHandlerInterface
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.sd_jwt.schema import VerifierChallenge
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.tools.utils import iat_now
from pyeudiw.openid4vp.exceptions import NotKBJWT, MissingIssuer
from pyeudiw.trust.exceptions import InvalidJwkMetadataException
from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.sd_jwt.exceptions import UnsupportedSdAlg, InvalidKeyBinding
from pyeudiw.sd_jwt.schema import is_sd_jwt_kb_format
from pyeudiw.openid4vp.vp_mdoc_cbor import VpMDocCbor
from pyeudiw.openid4vp.exceptions import MdocCborValidationError, VPExpired



class ResponseHandler(ResponseHandlerInterface):
    _SUPPORTED_RESPONSE_METHOD = "post"
    _SUPPORTED_RESPONSE_CONTENT_TYPE = "application/x-www-form-urlencoded"
    _ACCEPTED_ISSUER_METADATA_TYPE = "openid_credential_issuer"

    def _extract_all_user_attributes(self, extracted_attributess: dict) -> dict:
        # for all the valid credentials, take the payload and the disclosure and disclose user attributes
        # returns the user attributes ...
        all_user_attributes = dict()
        for i in extracted_attributess.values():
            all_user_attributes.update(**i)
        return all_user_attributes

    def _retrieve_session_from_state(self, state: str) -> dict:
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
            raise AuthorizeUnmatchedResponse(
                f"unable to find document-session associated to state {state}", err
            )

        if not request_session:
            raise InvalidInternalStateError(
                f"unable to find document-session associated to state {state}"
            )

        if request_session.get("finalized", True):
            raise FinalizedSessionError(
                f"cannot accept response: session for state {state} corrupted or already finalized"
            )

        nonce = request_session.get("nonce", None)
        if not nonce:
            raise InvalidInternalStateError(
                f"unable to find nonce in session associated to state {state}: corrupted data"
            )
        return request_session
    
    def _handle_error_response(self, error_response: ErrorResponsePayload) -> JsonResponse:
        request_session: dict = {}
        request_session = self._retrieve_session_from_state(error_response.state)

        self.db_engine.update_response_object(
            request_session["nonce"], error_response.state, asdict(error_response), True
        )

        self.db_engine.set_finalized(request_session["document_id"])

        return JsonResponse({"status": "OK"}, status="200")

    def response_endpoint(
        self, context: Context, *args: tuple
    ) -> Redirect | JsonResponse:
        self._log_function_debug("response_endpoint", context, "args", args)

        # parse and eventually decrypt jwt in response
        try:
            authz_payload = self._parse_authorization_response(context)
        except AuthRespParsingException as e400:
            return self._handle_400(
                context,
                "invalid authorization response: cannot parse the payload",
                e400
            )
        except AuthRespValidationException as e401:
            return self._handle_401(
                context,
                "invalid authentication method: token might be invalid or expired",
                e401,
            )
        self._log_debug(
            context, f"response URI endpoint response with payload {authz_payload}"
        )

        if isinstance(authz_payload, ErrorResponsePayload):
            return self._handle_error_response(authz_payload)

        request_session: dict = {}
        try:
            request_session = self._retrieve_session_from_state(authz_payload.state)
        except AuthorizeUnmatchedResponse as e400:
            return self._handle_400(
                context, 
                "invalid authorization response: cannot find the session associated to the state",
                e400
            )
        except InvalidInternalStateError as e500:
            return self._handle_500(context, e500.args[0], "invalid state")
        except FinalizedSessionError as e400:
            return self._handle_400(
                context, 
                "invalid authorization response: session already finalized or corrupted", 
                e400
            )

        # the flow below is a simplified algorithm of authentication response processing, where:
        # (1) we don't check that presentation submission matches definition (yet)
        # (2) we don't check that vp tokens are aligned with information declared in the presentation submission
        # (3) we use all disclosed claims in vp tokens to build the user identity
        extracted_attributes: dict[str, dict[str, Any]] = {}
        credential_issuers: list[str] = []
        encoded_vps: list[str] = (
            [authz_payload.vp_token]
            if isinstance(authz_payload.vp_token, str)
            else authz_payload.vp_token
        )

        for vp_token in encoded_vps:
            # verify vp token and extract user information
            if is_sd_jwt_kb_format(vp_token):
                try:
                    challenge = self._get_verifier_challenge(request_session)

                    token_processor = VpVcSdJwtParserVerifier(
                        vp_token, challenge["aud"], challenge["nonce"]
                    )

                    token_issuer = token_processor.get_issuer_name()

                    whitelisted_keys = self.trust_evaluator.get_public_keys(token_issuer)
                    token_processor.verify_signature(whitelisted_keys)
                    token_processor.verify_challenge()

                    if token_processor.is_expired() == True:
                        raise VPExpired("VP is expired")
                    
                    claims = token_processor.get_credentials()
                    iss = token_processor.get_issuer_name()

                    extracted_attributes[iss] = claims
                except MissingIssuer as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: missing issuer information",
                        e400
                    )
                except InvalidJwkMetadataException as e500:
                    return self._handle_500(
                        context, 
                        "trust error: cannot fetch public keys",
                        e500
                    )
                except JWSVerificationError as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: invalid signature",
                        e400
                    )
                except UnsupportedSdAlg as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: unsupported signature algorithm",
                        e400
                    )
                except InvalidKeyBinding as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: nonce or aud mismatch",
                        e400
                    )
                except ValueError as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: missing or invalid iat claim",
                        e400
                    )
                except VPExpired as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: expired",
                        e400
                    )
                except Exception as e400:
                    breakpoint()
                    return self._handle_400(
                        context, 
                        "trust error: cannot verify vp token",
                        e400
                    )
            else:
                try:
                    token_processor = VpMDocCbor(vp_token)
                except Exception as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: cannot parse vp token",
                        e400
                    )
                
                try:
                    token_processor.verify_signature()
                    if token_processor.is_expired() == True:
                        raise VPExpired("VP is expired")
                    
                    claims = token_processor.get_credentials()
                    doc_type = token_processor.get_doc_type()

                    extracted_attributes[doc_type] = claims
                except MdocCborValidationError as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: invalid signature",
                        e400
                    )
                except VPExpired as e400:
                    return self._handle_400(
                        context, 
                        "invalid vp token: expired",
                        e400
                    )
                except Exception as e400:
                    return self._handle_400(
                        context, 
                        "trust error: cannot verify vp token",
                        e400
                    )

        all_attributes = self._extract_all_user_attributes(extracted_attributes)
        iss_list_serialized = ";".join(credential_issuers)  # marshaling is whatever
        internal_resp = self._translate_response(
            all_attributes, iss_list_serialized, context
        )

        state = authz_payload.state
        response_code = self.response_code_helper.create_code(state)
        try:
            self.db_engine.update_response_object(
                request_session["nonce"], state, internal_resp
            )
            # authentication finalized!
            self.db_engine.set_finalized(request_session["document_id"])
            if self.effective_log_level == logging.DEBUG:
                request_session = self.db_engine.get_by_state(state=state)
                self._log_debug(
                    context, f"Session update on storage: {request_session}"
                )

        except StorageWriteError as e500:
            # TODO - do we have to block in the case the update cannot be done?
            self._log_error(context, f"Session update on storage failed: {e500}")
            return self._handle_500(
                context, 
                "Update error: Cannot update response object.", 
                e500
            )

        try:
            flow_type = RemoteFlowType(request_session["remote_flow_typ"])
        except Exception as e500:
            self._log_error(
                context, f"unable to identify flow from stored session: {e500}"
            )
            return self._handle_500(
                context, 
                "flow error: unable to identify flow from stored session", 
                e500
            )
        
        if flow_type == RemoteFlowType.SAME_DEVICE:
            cb_redirect_uri = f"{self.registered_get_response_endpoint}?response_code={response_code}"
            return JsonResponse({"redirect_uri": cb_redirect_uri}, status="200")
        else:
            return JsonResponse({"status": "OK"}, status="200")

    def _translate_response(
        self, response: dict, issuer: str, context: Context
    ) -> InternalData:
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
        timestamp_epoch = response.get("auth_time") or response.get("iat") or iat_now()
        timestamp_dt = datetime.datetime.fromtimestamp(
            timestamp_epoch, datetime.timezone.utc
        )
        timestamp_iso = timestamp_dt.isoformat().replace("+00:00", "Z")

        auth_class_ref = (
            response.get("acr")
            or response.get("amr")
            or self.config["authorization"]["default_acr_value"]
        )
        auth_info = AuthenticationInformation(auth_class_ref, timestamp_iso, issuer)

        # TODO - ACR values
        internal_resp = InternalData(auth_info=auth_info)

        # (re)define the response subject
        sub = ""
        pepper = self.config.get("user_attributes", {})["subject_id_random_value"]
        for i in self.config.get("user_attributes", {}).get("unique_identifiers", []):
            if response.get(i):
                _sub = response[i]
                sub = hashlib.sha256(f"{_sub}~{pepper}".encode()).hexdigest()
                break

        if not sub:
            self._log(
                context,
                level="warning",
                message=(
                    "[USER ATTRIBUTES] Missing subject id from OpenID4VP presentation "
                    "setting a random one for interop for internal frontends"
                ),
            )
            sub = hashlib.sha256(
                f"{json.dumps(response).encode()}~{pepper}".encode()
            ).hexdigest()
        response["sub"] = [sub]

        internal_resp.attributes = self.converter.to_internal("openid4vp", response)
        internal_resp.subject_id = sub
        return internal_resp

    def _parse_authorization_response(
        self, context: Context
    ) -> Union[AuthorizeResponsePayload, ErrorResponsePayload]:
        response_mode = detect_response_mode(context)
        match response_mode:
            case ResponseMode.direct_post:
                parser = DirectPostParser()
                return parser.parse_and_validate(context)
            case ResponseMode.direct_post_jwt:
                jwe_decrypter = JWEHelper(self.config["metadata_jwks"])
                parser = DirectPostJwtJweParser(jwe_decrypter)
                return parser.parse_and_validate(context)
            case ResponseMode.error:
                return ErrorResponsePayload(**context.request)
            case _:
                raise AuthRespParsingException(
                    f"invalid or unrecognized response mode: {response_mode}",
                    Exception("invalid program state"),
                )

    def _get_verifier_challenge(self, session_data: dict) -> VerifierChallenge:
        # TODO: check aud according to the LSP Potential singularities ...
        return {"aud": self.client_id, "nonce": session_data["nonce"]}
