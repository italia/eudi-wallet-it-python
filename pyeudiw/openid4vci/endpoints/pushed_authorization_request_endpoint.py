import secrets

from pydantic import ValidationError
from satosa.context import Context

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.models.openid4vci_basemodel import (
    ENDPOINT_CTX,
    CONFIG_CTX,
    CLIENT_ID_CTX,
    ENTITY_ID_CTX
)
from pyeudiw.openid4vci.models.par_request import ParRequest
from pyeudiw.openid4vci.models.par_response import ParResponse
from pyeudiw.openid4vci.storage.engine import OpenId4VciEngine
from pyeudiw.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method,
    validate_oauth_client_attestation
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    FORM_URLENCODED
)
from pyeudiw.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)

CLASS_NAME = "ParHandler.pushed_authorization_request_endpoint"

class ParHandler(BaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
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
        self.db_engine = OpenId4VciEngine.db_engine

    def endpoint(self, context: Context):
        """
        Handle a POST request to the pushed_authorization_endpoint (PAR).
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
            oauth_attestation = validate_oauth_client_attestation(context)

            data = self._get_body(context) or {}

            client_id = data.get("client_id", "").strip()
            request = data.get("request", "").strip()

            if not client_id or not request:
                self._log_error(
                    CLASS_NAME,
                    f"invalid request parameters for `par` endpoint, missing {'client_id' if not client_id else 'request'}"
                )
                return self._handle_400(context, "invalid request parameters")

            if oauth_attestation["thumbprint"] != client_id:
                self._log_error(
                    CLASS_NAME,
                    "invalid client_id parameter for `par`, value not matching with thumbprint of `OAuth-Client-Attestation-PoP`"
                )
                return self._handle_400(context, "invalid `client_id` parameters")

            decoded_request = self.jws_helper.verify(request)
            par_request = ParRequest.model_validate(
                decoded_request, context = {
                    ENDPOINT_CTX: "par",
                    CONFIG_CTX: self.config,
                    CLIENT_ID_CTX: client_id,
                    ENTITY_ID_CTX: self.entity_id
                })
            random_part = secrets.token_hex(16)
            self._init_db_session(context, random_part, par_request)
            return ParResponse.to_created_response(
                self._to_request_uri(random_part),
                self.config_utils.get_jwt().par_exp
            )
        except (InvalidRequestException, InvalidScopeException, ValidationError) as e:
            return self._handle_400(context, self._handle_validate_request_error(e, "credential"), e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke par endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke par endpoint", e)

    def _init_db_session(self, context: Context, request_uri_part: str, par_request: ParRequest):
        """
        Initialize a new DB session for a credential issuance flow.
        Args:
            context (Context): The SATOSA context.
            request_uri_part (str): The generated URI part.
            par_request (ParRequest): The validated request data.
        Raises:
            Exception: If the DB operation fails.
        """
        entity = OpenId4VCIEntity.new_entity(context, request_uri_part, par_request)
        try:
            self.db_engine.init_session(entity)
        except Exception as e500:
            self._log_critical(
                e500.__class__.__name__,
                f"Error while initializing session with state {entity.state} and {entity.session_id}: {e500}"
            )
            raise e500