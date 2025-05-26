import json
import logging
import secrets
from urllib.parse import parse_qs

from pyeudiw.jwt.jws_helper import JWSHelper
from satosa.context import Context
from satosa.response import Created, Redirect

from satosa_openid4vci.exceptions.bad_request_exception import \
    InvalidRequestException, InvalidScopeException
from satosa_openid4vci.models.authorization_request import AuthorizationRequest
from satosa_openid4vci.models.par_request import ParRequest
from satosa_openid4vci.models.token_request import TokenRequest
from satosa_openid4vci.storage.mongo_storage import MongoStorage
from satosa_openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from satosa_openid4vci.utils.content_type import ContentTypeUtils, \
    CONTENT_TYPE_HEADER, APPLICATION_JSON, FORM_URLENCODED
from satosa_openid4vci.utils.response import ResponseUtils

logger = logging.getLogger(__name__)


class Openid4VCIEndpoints:
    """Handles all the Entity endpoints"""

    def __init__(self, config):
        self.config = config
        # to be inizialized by .db_engine() property
        self._db_engine = None

    def pushed_authorization_endpoint(self, context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.get_header(CONTENT_TYPE_HEADER), FORM_URLENCODED)
            self._validate_oauth_client_attestation(context)

            body = context.request.body.decode("utf-8")
            data = parse_qs(body)

            client_id = data.get("client_id", [None])[0]
            request = data.get("request", [None])[0]

            if not client_id or not request:
                logger.error(f"invalid request parameters for `par` endpoint, missing {'client_id' if not client_id else 'request'}")
                return ResponseUtils.to_invalid_request_resp("invalid request parameters")

            helper = JWSHelper(self.config("metadata_jwks"))
            decoded_request = helper.verify(request)
            ParRequest.model_validate(
                    decoded_request,
                context = {"config": self.config, "client_id": client_id})
            random_part = secrets.token_hex(16)
            request_uri = f"urn:ietf:params:oauth:request_uri:{random_part}"
            self._init_db_session(context, request_uri)
            return Created(
                json.dumps({"request_uri": request_uri, "expires_in": 90}),
                content=APPLICATION_JSON,
            )
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke par endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke par endpoint")

    def authorization_endpoint(self, context):
        url = ""
        state = ""
        try:
            self._validate_request_method(context.request_method, ["POST", "GET"])
            if context.request_method == "POST":
                self._validate_content_type(context.get_header(CONTENT_TYPE_HEADER), FORM_URLENCODED)
                auth_req = dict(context.request.query)
            else:
                auth_req = parse_qs(context.request.body.decode("utf-8"))

            entity = self.db_engine.get_by_session_id(context.state["SESSION_ID"])
            par_obj = {
                "request_uri": f"urn:ietf:params:oauth:request_uri:{entity.request_uri_part}"
            }
            AuthorizationRequest.model_validate(
                auth_req,
                context = {"par_obj": par_obj}
            )

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

    def token_endpoint(self, context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.get_header(CONTENT_TYPE_HEADER), FORM_URLENCODED)
            self._validate_oauth_client_attestation(context)
            helper = JWSHelper(self.config("metadata_jwks"))
            decoded_request = helper.verify(context.request.body.decode("utf-8"))
            TokenRequest.model_validate(decoded_request)
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke token endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke token endpoint")

    def nonce_endpoint(self, context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.get_header(CONTENT_TYPE_HEADER), APPLICATION_JSON)
            #TODO: if body present throw exception
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke nonce endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke nonce endpoint")

    def credential_endpoint(self, context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.get_header(CONTENT_TYPE_HEADER), APPLICATION_JSON)
            self._validate_oauth_client_attestation(context)
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke credential endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke credential endpoint")

    def deferred_credential_endpoint(self, context):
        try:
            pass
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke deferred endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke deferred endpoint")

    def notification_endpoint(self, context):
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.get_header(CONTENT_TYPE_HEADER), APPLICATION_JSON)
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke notification endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke notification endpoint")

    #def status_assertion_endpoint(self, context):
    #def revocation_endpoint(self, context):

    def _validate_content_type(self, content_type_header: str, accepted_content_type: str):
        if (accepted_content_type == FORM_URLENCODED
            and not ContentTypeUtils.is_form_urlencoded(content_type_header)):
            logger.error(f"Invalid content-type for check `{FORM_URLENCODED}`: {content_type_header}")
            raise InvalidRequestException("invalid content-type")
        elif (accepted_content_type == APPLICATION_JSON
            and not ContentTypeUtils.is_application_json(content_type_header)):
            logger.error(f"Invalid content-type for check `{APPLICATION_JSON}`: {content_type_header}")
            raise InvalidRequestException("invalid content-type")

    def _validate_request_method(self, request_method, accepted_methods: list[str]):
        if request_method not in accepted_methods:
            logger.error(f"endpoint invoked with wrong request method: {request_method}")
            raise InvalidRequestException("invalid request method")

    def _validate_oauth_client_attestation(self, context):
        if not context.get_header("OAuth-Client-Attestation") or not context.get_header("OAuth-Client-Attestation-PoP"):
            logger.error(f"Missing r{'OAuth-Client-Attestation' if not context.get_header("OAuth-Client-Attestation") else 'OAuth-Client-Attestation-PoP'} header for `par` endpoint")
            raise InvalidRequestException("Missing Wallet Attestation JWT header")

    def _init_db_session(self, context: Context, request_uri_part: str):
        # Init session
        entity = OpenId4VCIEntity.new_entity(context,request_uri_part)
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