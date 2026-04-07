import secrets

from cryptojwt.jwk.jwk import key_from_jwk_dict
from pydantic import ValidationError
from satosa.context import Context

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import (
    POST_ACCEPTED_METHODS,
    VCIBaseEndpoint,
)
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import (
    CLIENT_ID_CTX,
    CONFIG_CTX,
    ENDPOINT_CTX,
    ENTITY_ID_CTX,
)
from pyeudiw.satosa.frontends.openid4vci.models.par_request import (
    ParRequest,
    SignedParRequest,
)
from pyeudiw.satosa.frontends.openid4vci.models.par_response import ParResponse
from pyeudiw.satosa.frontends.openid4vci.storage.engine import OpenId4VciDBEngineHandler
from pyeudiw.satosa.frontends.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidScopeException
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_oauth_client_attestation,
    validate_oauth_client_attestation_pop,
    validate_request_method, OAUTH_CLIENT_ATTESTATION_POP_HEADER, OAUTH_CLIENT_ATTESTATION_HEADER,
)
from pyeudiw.tools.content_type import FORM_URLENCODED, HTTP_CONTENT_TYPE_HEADER

CLASS_NAME = "ParHandler.pushed_authorization_request_endpoint"


class ParHandler(VCIBaseEndpoint):

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        *args,
    ):
        """
        Initialize the par endpoints class.

        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """

        super().__init__(config, internal_attributes, base_url, name)
        self.db_engine = OpenId4VciDBEngineHandler(config).db_engine
        self.force_same_device_flow_referer_criteria = self.config.get(
            "force_same_device_flow_referer_criteria"
        )
        self.federation_config = self.config.get("trust", {}).get("federation", {}).get("config", {})

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
                self._log_error(
                    CLASS_NAME,
                    "invalid request parameters for `par` endpoint, missing request method",
                )
                return self._handle_500(
                    context,
                    "invalid request parameters",
                    Exception("invalid request parameters"),
                )

            if not context.http_headers:
                self._log_error(
                    CLASS_NAME,
                    "invalid request parameters for `par` endpoint, missing HTTP headers",
                )
                return self._handle_500(
                    context,
                    "invalid request parameters",
                    Exception("invalid request parameters"),
                )

            validate_request_method(context.request_method, POST_ACCEPTED_METHODS)
            validate_content_type(
                context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED
            )

            data = self._get_body(context) or {}

            # RFC 9126 Section 4.2: MUST reject PAR request if it contains request_uri
            if data.get("request_uri"):
                self._log_error(
                    CLASS_NAME,
                    "invalid request parameters for `par` endpoint, request_uri must not be present",
                )
                return self._handle_400(
                    context,
                    "invalid request parameters: request_uri must not be present",
                )

            client_id = data.get("client_id", "").strip()

            if not client_id:
                self._log_error(
                    CLASS_NAME,
                    f"invalid request parameters for `par` endpoint, missing {'client_id' if not client_id else 'request'}",
                )
                return self._handle_400(context, "invalid request parameters")

            if self.wallet_attestation_required:
                try:
                    header_client_attestation = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER)
                    oauth_attestation = validate_oauth_client_attestation(header_client_attestation,
                                                                          self.federation_config.get("authority_hints"),
                                                                          self.federation_config.get("httpc_params"),
                                                                          self.client_attestation_signing_alg_values_supported)

                    cnf_key = oauth_attestation.get("cnf", {}).get("jwk", {})
                    pop_attestation = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER)
                    validate_oauth_client_attestation_pop(pop_attestation,
                                                          cnf_key,
                                                          self.client_attestation_pop_signing_alg_values_supported)

                except InvalidRequestException as e:
                    self._log_error(
                        e.__class__.__name__,
                        f"Error during OAuth client attestation validation in `par` endpoint: {e}",
                    )
                    return self._handle_400(context, str(e), e)

                if key_from_jwk_dict(cnf_key).thumbprint("SHA-256").decode() != client_id: #reference RFC 6749 + IT-WALLET 1.3.3 IT specifications
                    self._log_error(
                        CLASS_NAME,
                        "invalid request parameters for `par` endpoint, invalid client_id in PAR request",
                    )
                    return self._handle_400(
                        context,
                        "invalid request parameters",
                        Exception("invalid request parameters"),
                    )

            request = data.get("request", "").strip()

            if request and self.wallet_attestation_required and (
                self.signed_par_request == "true" or self.signed_par_request == "both"
            ):
                try:
                    jws_helper = JWSHelper(cnf_key) #todo check if it is right key
                    payload = jws_helper.verify(request)

                    if not isinstance(payload, dict):
                        self._log_error(
                            CLASS_NAME,
                            f"invalid request parameter for `par`, invalid JWS: {request}",
                        )
                        return self._handle_400(context, "invalid request parameters")

                    par_request = SignedParRequest.model_validate(
                        payload,
                        context={
                            ENDPOINT_CTX: "par",
                            CONFIG_CTX: self.config,
                            CLIENT_ID_CTX: client_id,
                            ENTITY_ID_CTX: self.entity_id,
                        },
                    )

                except JWSVerificationError:
                    self._log_error(
                        CLASS_NAME,
                        f"invalid request parameter for `par`, invalid JWS: {request}",
                    )
                    return self._handle_400(context, "invalid request parameters")
            elif (
                self.signed_par_request == "false" or self.signed_par_request == "both"
            ):
                par_request = ParRequest.model_validate(
                    data,
                    context={
                        ENDPOINT_CTX: "par",
                        CONFIG_CTX: self.config,
                        CLIENT_ID_CTX: client_id,
                        ENTITY_ID_CTX: self.entity_id,
                    },
                )
            else:
                self._log_error(
                    CLASS_NAME,
                    "invalid request parameters for `par` endpoint, missing request or signed request",
                )
                return self._handle_400(context, "invalid request parameters")

            if isinstance(
                par_request, SignedParRequest
            ) and self.db_engine.is_par_jti_replay(client_id, par_request.jti):
                self._log_error(
                    CLASS_NAME,
                    "invalid request parameters for `par` endpoint, jti replay detected",
                )
                return self._handle_400(
                    context, "invalid request parameters: jti replay detected"
                )

            random_part = secrets.token_hex(16)
            self._init_db_session(context, random_part, par_request)

            return ParResponse.to_created_response(
                self._to_request_uri(random_part),
                self.config_utils.get_jwt().par_exp or 0,
            )
        except (InvalidRequestException, InvalidScopeException, ValidationError) as e:
            return self._handle_400(
                context, self._handle_validate_request_error(e, "credential"), e
            )
        except Exception as e:
            self._log_error(
                e.__class__.__name__, f"Error during invoke par endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke par endpoint", e)

    def _init_db_session(
        self,
        context: Context,
        request_uri_part: str,
        par_request: ParRequest | SignedParRequest,
    ):
        """
        Initialize a new DB session for a credential issuance flow.

        Args:
            context (Context): The SATOSA context.
            request_uri_part (str): The generated URI part.
            par_request (ParRequest | SignedParRequest): The validated request data.
        Raises:
            Exception: If the DB operation fails.
        """

        entity = OpenId4VCIEntity.new_entity(
            context,
            request_uri_part,
            par_request,
            self.force_same_device_flow_referer_criteria,
        )
        try:
            self.db_engine.upsert_session(entity.session_id, entity.model_dump())
        except Exception as e500:
            self._log_critical(
                e500.__class__.__name__,
                f"Error while initializing session with state {entity.state} and {entity.session_id}: {e500}",
            )
            raise e500

    def _validate_configs(self):
        self._validate_required_configs(
            [
                ("jwt.par_exp", self.config_utils.get_jwt().par_exp),
                (
                    "metadata.openid_credential_issuer.credential_configurations_supported",
                    self.config_utils.get_credential_configurations_supported(),
                ),
            ]
        )
        oauth_authorization_server = self.config_utils.get_oauth_authorization_server()
        if not oauth_authorization_server:
            self._validate_required_configs(
                [
                    (
                        "metadata.oauth_authorization_server",
                        self.config_utils.get_oauth_authorization_server(),
                    )
                ]
            )
        self._validate_required_configs(
            [
                (
                    "metadata.oauth_authorization_server.response_types_supported",
                    oauth_authorization_server.response_types_supported,
                ),
                (
                    "metadata.oauth_authorization_server.response_modes_supported",
                    oauth_authorization_server.response_modes_supported,
                ),
                (
                    "metadata.oauth_authorization_server.code_challenge_methods_supported",
                    oauth_authorization_server.code_challenge_methods_supported,
                ),
            ]
        )
