from typing import Any

from satosa.context import Context

from copy import copy
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vp.authorization_request import build_authorization_request_claims
from pyeudiw.presentation_definition.utils import DUCKLE_PRESENTATION, DUCKLE_QUERY_KEY
from pyeudiw.satosa.interfaces.request_handler import RequestHandlerInterface
from pyeudiw.satosa.utils.response import Response
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.openid4vp.schemas.wallet_metadata import WalletPostRequest
from pyeudiw.jwt.exceptions import JWSSigningError


class RequestHandler(RequestHandlerInterface, BaseLogger):

    _REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
    _RESP_CONTENT_TYPE = f"application/{_REQUEST_OBJECT_TYP}"

    def request_endpoint(self, context: Context, *args) -> Response:
        self._log_function_debug("request_endpoint", context, "args", args)

        if context.request_method == "GET":
            try:
                state = context.qs_params["id"]

                if not state:
                    raise ValueError("state is missing")
            except Exception as e400:
                return self._handle_400(
                    context, 
                    "request error: missing or invalid parameter [id]",
                    e400
                )
            
            try:
                document = self.db_engine.get_by_state(state)
                if not document:
                    raise ValueError("session not found")
            except ValueError as e401:
                return self._handle_401(
                    context, 
                    "session error: cannot find the session associated to the state",
                    e401
                )
            except Exception as e500:
                return self._handle_500(
                    context,
                    "session error: cannot retrieve the session",
                    e500,
                )

        else:
            try:
                if not context.state or "SESSION_ID" not in context.state:
                    raise ValueError("session_id is missing")
                
                session_id = context.state["SESSION_ID"]

                if not session_id:
                    raise ValueError("session_id is missing")
            except Exception as e400:
                return self._handle_400(
                    context, 
                    "request error: missing or invalid parameter [SESSION_ID]",
                    e400
                )
            
            try:
                document = self.db_engine.get_by_session_id(session_id)
                if not document:
                    raise ValueError("session not found")
            except ValueError as e401:
                return self._handle_401(
                    context, 
                    "session error: cannot find the session associated to the session_id",
                    e401
                )
            except Exception as e500:
                return self._handle_500(
                    context,
                    "session error: cannot retrieve the session",
                    e500,
                )
        
        try:
            client_metadata = self.trust_evaluator.get_metadata(self.client_id)
        except Exception:
            client_metadata = None

        if context.request_method == "POST":
            try:
                wallet_post_request = WalletPostRequest(**context.request)
            except Exception as e:
                self._log_warning(context, f"wallet metadata not provided or invalid: {e}")
                wallet_post_request = WalletPostRequest(
                    wallet_metadata=None,
                    wallet_nonce=None,
                )
        else:
            wallet_post_request = WalletPostRequest(
                wallet_metadata=None,
                wallet_nonce=None,
            )

        data = build_authorization_request_claims(
            self.client_id,
            document["state"],
            self.absolute_response_url,
            self.config["authorization"],
            client_metadata=client_metadata,
            submission_data=self._build_submission_data(),
            wallet_nonce=wallet_post_request.wallet_nonce,
        )


        if _aud := self.config["authorization"].get("aud"):
            data["aud"] = _aud
        # take the session created in the pre-request authz endpoint
        try:
            document_id = document["document_id"]

            data_copy = copy(data)
            if wallet_post_request.wallet_metadata:
                data_copy["wallet_metadata"] = wallet_post_request.wallet_metadata.model_dump()

            self.db_engine.update_request_object(document_id, data_copy)

        except ValueError as e401:
            return self._handle_401(
                context, 
                "session error: cannot find the session associated to the state",
                e401
            )
        except Exception as e500:
            return self._handle_500(
                context,
                "session error: cannot update the session",
                e500,
            )

        _protected_jwt_headers = {
            "typ": RequestHandler._REQUEST_OBJECT_TYP,
        }

        # load all the trust handlers request jwt header parameters, if any
        trust_params = self.trust_evaluator.get_jwt_header_trust_parameters(issuer=self.client_id)
        _protected_jwt_headers.update(trust_params)

        if ("x5c" in _protected_jwt_headers) or ("kid" in _protected_jwt_headers):
            # let helper decide which key best fit the given header, otherise use default hich is the first confgiured key
            helper = JWSHelper(self.config["metadata_jwks"])
        else:
            helper = JWSHelper(self.default_metadata_private_jwk)

        alg_values_supported = (wallet_post_request.wallet_metadata.alg_values_supported if wallet_post_request.wallet_metadata else []) or []

        try:
            request_object_jwt = helper.sign(
                data,
                protected=_protected_jwt_headers,
                signing_algs=alg_values_supported,
            )
            self._log_debug(context, f"created request object {request_object_jwt}")
            return Response(
                message=request_object_jwt,
                status="200",
                content=RequestHandler._RESP_CONTENT_TYPE,
            )
        except JWSSigningError as e400:
            return self._handle_400(
                context,
                "request error: cannot sign the request object, possibly due to a non supported algorithm",
                e400,
            )
        except Exception as e500:
            return self._handle_500(
                context,
                "internal error: error while processing the request object",
                e500,
            )

    def _build_submission_data(self) -> dict[str, Any]:
        if DUCKLE_PRESENTATION in self.config:
            return {
                DUCKLE_QUERY_KEY: self.config.get(DUCKLE_PRESENTATION)[DUCKLE_QUERY_KEY],
                "typo": DUCKLE_PRESENTATION
            }
        else:
            return None
