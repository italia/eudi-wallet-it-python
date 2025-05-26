import json
import logging
import secrets
from urllib.parse import parse_qs

from satosa.context import Context
from satosa.response import Created, Redirect

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.exceptions.bad_request_exception import \
    InvalidRequestException, InvalidScopeException
from pyeudiw.openid4vci.models.authorization_request import AuthorizationRequest, PAR_REQUEST_URI_CTX
from pyeudiw.openid4vci.models.credential_offer_request import CredentialOfferRequest
from pyeudiw.openid4vci.models.openid4vci_basemodel import CONFIG_CTX
from pyeudiw.openid4vci.models.par_request import ParRequest, CLIENT_ID_CTX, ENTITY_ID_CTX
from pyeudiw.openid4vci.models.par_response import ParResponse
from pyeudiw.openid4vci.models.token_request import TokenRequest
from pyeudiw.openid4vci.storage.mongo_storage import MongoStorage
from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from pyeudiw.openid4vci.utils.config import Config
from pyeudiw.openid4vci.utils.content_type import ContentTypeUtils, \
    HTTP_CONTENT_TYPE_HEADER, APPLICATION_JSON, FORM_URLENCODED
from pyeudiw.openid4vci.utils.response import ResponseUtils

logger = logging.getLogger(__name__)


class Openid4VCIEndpoints:
    """Handles all the Entity endpoints"""

    def __init__(self,
                 config: dict,
                 base_url: str,
                 name: str):
        self.config = config
        self.config_utils = Config(config)
        # to be inizialized by .db_engine() property
        self._db_engine = None
        self._backend_url = f"{base_url}/{name}"
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])

    def credential_offer_endpoint(self, context: Context):
        try:
            self._validate_request_method(context.request_method, ["GET"])
            self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            CredentialOfferRequest.model_validate(
                context.request.query, context = {
                    CONFIG_CTX: self.config_utils
                })
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke credential_offer endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke credential_offer endpoint")

    def pushed_authorization_endpoint(self, context: Context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
            self._validate_oauth_client_attestation(context)

            body = context.request.body.decode("utf-8")
            data = parse_qs(body)

            client_id = data.get("client_id", [None])[0]
            request = data.get("request", [None])[0]

            if not client_id or not request:
                logger.error(f"invalid request parameters for `par` endpoint, missing {'client_id' if not client_id else 'request'}")
                return ResponseUtils.to_invalid_request_resp("invalid request parameters")

            decoded_request = self.jws_helper.verify(request)
            par_request = ParRequest.model_validate(
                    decoded_request, context = {
                    CONFIG_CTX: self.config_utils,
                    CLIENT_ID_CTX: client_id,
                    ENTITY_ID_CTX: self.entity_id
                })
            random_part = secrets.token_hex(16)
            self._init_db_session(context, random_part, par_request)
            return ParResponse.to_created_response(
                self._to_request_uri(random_part),
                self.config_utils.get_jwt_default_exp()
            )
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke par endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke par endpoint")

    def authorization_endpoint(self, context: Context):
        url = ""
        state = ""
        try:
            self._validate_request_method(context.request_method, ["POST", "GET"])
            if context.request_method == "POST":
                self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
                auth_req = parse_qs(context.request.body.decode("utf-8"))
            else:
                auth_req = dict(context.request.query)

            entity = self.db_engine.get_by_session_id(context.state["SESSION_ID"])
            AuthorizationRequest.model_validate(
                auth_req, context = {
                    PAR_REQUEST_URI_CTX: self._to_request_uri(entity.request_uri_part)
                })

            return Redirect(
                f"{url}?code={code}&state={entity.state}&iss={iss}",
                content = FORM_URLENCODED
            )
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_redirect(
                url, e.message, state)
        except Exception as e:
            logger.error(f"Error during invoke par endpoint: {e}")
            return ResponseUtils.to_server_error_redirect(
                url,"error during invoke authorization endpoint", state)

    def token_endpoint(self, context: Context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
            self._validate_oauth_client_attestation(context)
            decoded_request = self.jws_helper.verify(context.request.body.decode("utf-8"))
            TokenRequest.model_validate(decoded_request)
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke token endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke token endpoint")

    def nonce_endpoint(self, context: Context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            #TODO: if body present throw exception
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke nonce endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke nonce endpoint")

    def credential_endpoint(self, context: Context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            self._validate_oauth_client_attestation(context)
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke credential endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke credential endpoint")

    def deferred_credential_endpoint(self, context: Context):
        try:
            pass
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke deferred endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke deferred endpoint")

    def notification_endpoint(self, context: Context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke notification endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke notification endpoint")

    #def status_assertion_endpoint(self, context: satosa.context.Context)
    #def revocation_endpoint(self, context: satosa.context.Context)
    @staticmethod
    def _to_request_uri(random_part: str):
        return f"urn:ietf:params:oauth:request_uri:{random_part}"

    @staticmethod
    def _validate_content_type(content_type_header: str, accepted_content_type: str):
        if (accepted_content_type == FORM_URLENCODED
            and not ContentTypeUtils.is_form_urlencoded(content_type_header)):
            logger.error(f"Invalid content-type for check `{FORM_URLENCODED}`: {content_type_header}")
            raise InvalidRequestException("invalid content-type")
        elif (accepted_content_type == APPLICATION_JSON
            and not ContentTypeUtils.is_application_json(content_type_header)):
            logger.error(f"Invalid content-type for check `{APPLICATION_JSON}`: {content_type_header}")
            raise InvalidRequestException("invalid content-type")

    @staticmethod
    def _validate_request_method(request_method: str, accepted_methods: list[str]):
        if request_method is None or request_method.upper() not in accepted_methods:
            logger.error(f"endpoint invoked with wrong request method: {request_method}")
            raise InvalidRequestException("invalid request method")

    @staticmethod
    def _validate_oauth_client_attestation(context: Context):
        if not context.http_headers["OAuth-Client-Attestation"] or not context.http_headers["OAuth-Client-Attestation-PoP"]:
            logger.error(f"Missing r{'OAuth-Client-Attestation' if not context.http_headers["OAuth-Client-Attestation"] else 'OAuth-Client-Attestation-PoP'} header for `par` endpoint")
            raise InvalidRequestException("Missing Wallet Attestation JWT header")

    def _init_db_session(self, context: Context, request_uri_part: str, par_request: ParRequest):
        # Init session
        entity = OpenId4VCIEntity.new_entity(context,request_uri_part, par_request)
        try:
            self.db_engine.init_session(entity)
        except Exception as e500:
            logger.error(
                f"Error while initializing session with state {entity.state} and {entity.session_id}: {e500}"
            )
            raise e500

    @property
    def db_engine(self) -> MongoStorage:
        """
        Returns the DBEngine instance used by the class
        """
        if not self._db_engine:
            self._db_engine = MongoStorage(self.config["storage"])

        try:
            self._db_engine.is_connected
        except Exception as e:
            if getattr(self, "_db_engine", None):
                logger.error(
                    f"OpenID4VCI db storage handling, connection check silently fails and get restored: {e}",
                )
            self._db_engine = MongoStorage(self.config["storage"])

        return self._db_engine

    @property
    def entity_id(self) -> str:
        if _cid := self.config_utils.get_openid_credential_issuer().credential_issuer:
            return _cid
        else:
            return self._backend_url
