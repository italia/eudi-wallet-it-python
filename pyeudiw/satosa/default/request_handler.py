import uuid

from satosa.context import Context

from pyeudiw.jwt import JWSHelper
from pyeudiw.satosa.exceptions import HTTPError, DPOPValidationError
from pyeudiw.satosa.interfaces.request_handler import RequestHandlerInterface
from pyeudiw.satosa.utils.dpop import BackendDPoP
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.satosa.utils.trust import BackendTrust
from pyeudiw.tools.utils import exp_from_now, iat_now


class RequestHandler(RequestHandlerInterface, BackendDPoP, BackendTrust):
    def check_DPOP(self, context: Context):
        try:
            self._request_endpoint_dpop(context)
        except DPOPValidationError as e:
            _msg = f"[DPoP VALIDATION ERROR] WIA evalution error: {e}."
            return self._handle_401(context, _msg, e)
        except Exception as e:
            _msg = f"[INTERNAL SERVER ERROR] {e}."
            return self._handle_500(context, _msg, e)
        return None

    def request_endpoint(self, context: Context, *args) -> JsonResponse:
        self._log_function_debug("response_endpoint", context, "args", args)

        try:
            state = context.qs_params["id"]
        except Exception as e:
            _msg = (
                "Error while retrieving id from qs_params: "
                f"{e.__class__.__name__}: {e}"
            )
            return self._handle_400(context, _msg, HTTPError(f"{e} with {context.__dict__}"))

        data = {
            "scope": ' '.join(self.config['authorization']['scopes']),
            "client_id_scheme": "entity_id",  # that's federation.
            "client_id": self.client_id,
            "response_mode": "direct_post.jwt",  # only HTTP POST is allowed.
            "response_type": "vp_token",
            "response_uri": self.absolute_response_url,
            "nonce": str(uuid.uuid4()),
            "state": state,
            "iss": self.client_id,
            "iat": iat_now(),
            "exp": exp_from_now(minutes=self.config['authorization']['expiration_time'])
        }

        # try:
        #     dpop_proof = context.http_headers['HTTP_DPOP']
        #     attestation = context.http_headers['HTTP_AUTHORIZATION']
        # except KeyError as e:
        #     _msg = f"Error while accessing http headers: {e}"
        #     return self._handle_400(context, _msg, HTTPError(f"{e} with {context.__dict__}"))

        # take the session created in the pre-request authz endpoint
        try:
            document = self.db_engine.get_by_state(state)
            document_id = document["document_id"]
            # self.db_engine.add_dpop_proof_and_attestation(
            #     document_id, dpop_proof, attestation
            # )
            self.db_engine.update_request_object(document_id, data)

        except ValueError as e:
            _msg = "Error while retrieving request object from database."
            return self._handle_500(context, _msg, HTTPError(f"{e} with {context.__dict__}"))

        except (Exception, BaseException) as e:
            _msg = f"Error while updating request object: {e}"
            return self._handle_500(context, _msg, e)

        helper = JWSHelper(self.default_metadata_private_jwk)

        jwt = helper.sign(
            data,
            protected={'trust_chain': self.get_backend_trust_chain()}
        )
        response = {"response": jwt}
        return JsonResponse(
            response,
            status="200"
        )
