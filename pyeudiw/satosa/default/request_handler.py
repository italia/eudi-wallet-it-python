from satosa.context import Context

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vp.authorization_request import build_authorization_request_claims
from pyeudiw.satosa.interfaces.request_handler import RequestHandlerInterface
from pyeudiw.satosa.utils.response import Response
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.jwk.parse import parse_b64der
from pyeudiw.jwk import JWK


class RequestHandler(RequestHandlerInterface, BaseLogger):

    _REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
    _RESP_CONTENT_TYPE = f"application/{_REQUEST_OBJECT_TYP}"

    def request_endpoint(self, context: Context, *args) -> Response:
        self._log_function_debug("request_endpoint", context, "args", args)

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
            metadata = self.trust_evaluator.get_metadata(self.client_id)
        except Exception:
            metadata = None

        data = build_authorization_request_claims(
            self.client_id,
            state,
            self.absolute_response_url,
            self.config["authorization"],
            metadata=metadata,
        )

        if _aud := self.config["authorization"].get("aud"):
            data["aud"] = _aud
        # take the session created in the pre-request authz endpoint
        try:
            document = self.db_engine.get_by_state(state)
            document_id = document["document_id"]
            self.db_engine.update_request_object(document_id, data)

        except ValueError as e401:
            return self._handle_401(
                context, 
                "session error: cannot find the session associated to the state",
                e401
            )
        except (Exception, BaseException) as e500:
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

        helper = JWSHelper(self.config["metadata_jwks"])

        try:
            request_object_jwt = helper.sign(
                data,
                protected=_protected_jwt_headers,
            )
            self._log_debug(context, f"created request object {request_object_jwt}")
            return Response(
                message=request_object_jwt,
                status="200",
                content=RequestHandler._RESP_CONTENT_TYPE,
            )
        except Exception as e500:
            return self._handle_500(
                context,
                "internal error: error while processing the request object",
                e500,
            )
