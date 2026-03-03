import secrets

from pydantic import ValidationError
from satosa.context import Context

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import VCIBaseEndpoint, POST_ACCEPTED_METHODS
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import ENDPOINT_CTX, CONFIG_CTX, CLIENT_ID_CTX, ENTITY_ID_CTX
from pyeudiw.satosa.frontends.openid4vci.models.par_request import SignedParRequest, ParRequest
from pyeudiw.satosa.frontends.openid4vci.models.par_response import ParResponse
from pyeudiw.satosa.frontends.openid4vci.storage.engine import OpenId4VciDBEngineHandler
from pyeudiw.satosa.frontends.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidScopeException
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method,
    validate_oauth_client_attestation,
    validate_oauth_client_attestation_pop,
)
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, FORM_URLENCODED

CLASS_NAME = "ParHandler.pushed_authorization_request_endpoint"


class ParHandler(VCIBaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str, *args):
        """
        Initialize the par endpoints class.

        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """

        super().__init__(config, internal_attributes, base_url, name)
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])
        self.db_engine = OpenId4VciDBEngineHandler(config).db_engine
        self.force_same_device_flow_referer_criteria = self.config.get("force_same_device_flow_referer_criteria")

    def endpoint(self, context: Context):
        """
        Handle a POST request to the pushed_authorization_endpoint (PAR).

        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """

        try:
            if not context.request_method:
                self._log_error(CLASS_NAME, "invalid request parameters for `par` endpoint, missing request method")
                return self._handle_500(context, "invalid request parameters", Exception("invalid request parameters"))

            if not context.http_headers:
                self._log_error(CLASS_NAME, "invalid request parameters for `par` endpoint, missing HTTP headers")
                return self._handle_500(context, "invalid request parameters", Exception("invalid request parameters"))

            validate_request_method(context.request_method, POST_ACCEPTED_METHODS)
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)

            data = self._get_body(context) or {}

            # RFC 9126 Section 4.2: MUST reject PAR request if it contains request_uri
            if data.get("request_uri"):
                self._log_error(CLASS_NAME, "invalid request parameters for `par` endpoint, request_uri must not be present")
                return self._handle_400(context, "invalid request parameters: request_uri must not be present")

            client_id = data.get("client_id", "").strip()

            if not client_id:
                self._log_error(CLASS_NAME, f"invalid request parameters for `par` endpoint, missing {'client_id' if not client_id else 'request'}")
                return self._handle_400(context, "invalid request parameters")

            if self.wallet_attestation_required:
                try:
                    validate_oauth_client_attestation_pop(context)
                    oauth_attestation = validate_oauth_client_attestation(context, self.dpop_signing_alg_values_supported)
                except InvalidRequestException as e:
                    self._log_error(e.__class__.__name__, f"Error during OAuth client attestation validation in `par` endpoint: {e}")
                    return self._handle_400(context, str(e), e)

                if not oauth_attestation or oauth_attestation["thumbprint"] != client_id:
                    self._log_error(CLASS_NAME, "invalid request parameters for `par` endpoint, missing OAuth-Client-Attestation-PoP")
                    return self._handle_400(context, "invalid request parameters", Exception("invalid request parameters"))

            request = data.get("request", "").strip()

            if request and (self.signed_par_request == "true" or self.signed_par_request == "both"):
                try:
                    payload = self.jws_helper.verify(request)

                    if not isinstance(payload, dict):
                        self._log_error(CLASS_NAME, f"invalid request parameter for `par`, invalid JWS: {request}")
                        return self._handle_400(context, "invalid request parameters")

                    par_request = SignedParRequest.model_validate(
                        payload, context={ENDPOINT_CTX: "par", CONFIG_CTX: self.config, CLIENT_ID_CTX: client_id, ENTITY_ID_CTX: self.entity_id}
                    )

                except JWSVerificationError:
                    self._log_error(CLASS_NAME, f"invalid request parameter for `par`, invalid JWS: {request}")
                    return self._handle_400(context, "invalid request parameters")
            elif self.signed_par_request == "false" or self.signed_par_request == "both":
                par_request = ParRequest.model_validate(
                    data, context={ENDPOINT_CTX: "par", CONFIG_CTX: self.config, CLIENT_ID_CTX: client_id, ENTITY_ID_CTX: self.entity_id}
                )
            else:
                self._log_error(CLASS_NAME, "invalid request parameters for `par` endpoint, missing request or signed request")
                return self._handle_400(context, "invalid request parameters")

            random_part = secrets.token_hex(16)
            self._init_db_session(context, random_part, par_request)

            return ParResponse.to_created_response(self._to_request_uri(random_part), self.config_utils.get_jwt().par_exp or 0)
        except (InvalidRequestException, InvalidScopeException, ValidationError) as e:
            return self._handle_400(context, self._handle_validate_request_error(e, "credential"), e)
        except Exception as e:
            self._log_error(e.__class__.__name__, f"Error during invoke par endpoint: {e}")
            return self._handle_500(context, "error during invoke par endpoint", e)

    def _init_db_session(self, context: Context, request_uri_part: str, par_request: ParRequest | SignedParRequest):
        """
        Initialize a new DB session for a credential issuance flow.

        Args:
            context (Context): The SATOSA context.
            request_uri_part (str): The generated URI part.
            par_request (ParRequest | SignedParRequest): The validated request data.
        Raises:
            Exception: If the DB operation fails.
        """

        entity = OpenId4VCIEntity.new_entity(context, request_uri_part, par_request, self.force_same_device_flow_referer_criteria)
        try:
            self.db_engine.upsert_session(entity.session_id, entity.model_dump())
        except Exception as e500:
            self._log_critical(e500.__class__.__name__, f"Error while initializing session with state {entity.state} and {entity.session_id}: {e500}")
            raise e500

    def _validate_configs(self):
        self._validate_required_configs(
            [
                ("jwt.par_exp", self.config_utils.get_jwt().par_exp),
                ("metadata.openid_credential_issuer.credential_configurations_supported", self.config_utils.get_credential_configurations_supported()),
            ]
        )
        oauth_authorization_server = self.config_utils.get_oauth_authorization_server()
        if not oauth_authorization_server:
            self._validate_required_configs([("metadata.oauth_authorization_server", self.config_utils.get_oauth_authorization_server())])
        self._validate_required_configs(
            [
                ("metadata.oauth_authorization_server.response_types_supported", oauth_authorization_server.response_types_supported),
                ("metadata.oauth_authorization_server.response_modes_supported", oauth_authorization_server.response_modes_supported),
                ("metadata.oauth_authorization_server.code_challenge_methods_supported", oauth_authorization_server.code_challenge_methods_supported),
            ]
        )
