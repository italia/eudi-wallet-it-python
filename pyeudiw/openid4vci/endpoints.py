import logging
import secrets
import time
from os import access
from urllib.parse import parse_qs

from pydantic import BaseModel
from satosa.context import Context

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.exceptions.bad_request_exception import \
    InvalidRequestException, InvalidScopeException
from pyeudiw.openid4vci.models.authorization_request import AuthorizationRequest, PAR_REQUEST_URI_CTX
from pyeudiw.openid4vci.models.authorization_response import AuthorizationResponse
from pyeudiw.openid4vci.models.credential_offer_request import CredentialOfferRequest
from pyeudiw.openid4vci.models.openid4vci_basemodel import CONFIG_CTX, CLIENT_ID_CTX, ENDPOINT_CTX
from pyeudiw.openid4vci.models.par_request import ParRequest, ENTITY_ID_CTX
from pyeudiw.openid4vci.models.par_response import ParResponse
from pyeudiw.openid4vci.models.token import AccessToken, RefreshToken
from pyeudiw.openid4vci.models.token_request import TokenRequest, REDIRECT_URI_CTX, CODE_CHALLENGE_CTX, \
    CODE_CHALLENGE_METHOD_CTX
from pyeudiw.openid4vci.models.token_response import TokenResponse
from pyeudiw.openid4vci.storage.mongo_storage import MongoStorage
from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from pyeudiw.openid4vci.utils.config import Config
from pyeudiw.openid4vci.utils.content_type import ContentTypeUtils, \
    HTTP_CONTENT_TYPE_HEADER, APPLICATION_JSON, FORM_URLENCODED
from pyeudiw.openid4vci.utils.response import ResponseUtils

logger = logging.getLogger(__name__)

class Openid4VCIEndpoints:
    """
    Class that handles OpenID4VCI endpoints for credential issuance.

    This class manages all incoming requests related to:
    - Credential Offer
    - Pushed Authorization
    - Authorization
    - Token issuance
    - Nonce generation
    - Credential issuance
    - Deferred credential
    - Notification

    Attributes:
        config (dict): Configuration dictionary.
        config_utils (Config): Utility wrapper for config access.
        _db_engine (MongoStorage): Storage backend, initialized lazily.
        _backend_url (str): Full base URL for all endpoints.
        jws_helper (JWSHelper): Utility for verifying and decoding JWS tokens.
    """

    def __init__(self, config: dict, base_url: str, name: str):
        """
        Initialize the OpenID4VCI endpoints class.
        Args:
            config (dict): The configuration dictionary.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        self.config = config
        self.config_utils = Config(config)
        self._db_engine = None
        self._backend_url = f"{base_url}/{name}"
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])

    def credential_offer_endpoint(self, context: Context):
        """
        Handle a GET request to the credential_offer endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
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
        """
        Handle a POST request to the pushed_authorization_endpoint (PAR).
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
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
                **decoded_request, context = {
                    ENDPOINT_CTX: "par",
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
        """
        Handle an authorization request, via GET or POST.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object, usually a redirect.
        """
        global entity
        try:
            entity = self.db_engine.get_by_session_id(self._get_session_id(context))
            self._validate_request_method(context.request_method, ["POST", "GET"])
            if context.request_method == "POST":
                self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
                auth_req = parse_qs(context.request.body.decode("utf-8"))
            else:
                auth_req = dict(context.request.query)

            AuthorizationRequest.model_validate(
                **auth_req, context = {
                    PAR_REQUEST_URI_CTX: self._to_request_uri(entity.request_uri_part),
                    CLIENT_ID_CTX: entity.client_id
                })
            return AuthorizationResponse(
                state=entity.state,
                iss=self.entity_id,
            ).to_redirect_response(entity.redirect_uri)
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_redirect(
                getattr(entity, "redirect_uri", None), e.message, getattr(entity, "state", None))
        except Exception as e:
            logger.error(f"Error during invoke par endpoint: {e}")
            return ResponseUtils.to_server_error_redirect(
                getattr(entity, "redirect_uri", None),"error during invoke authorization endpoint",
                getattr(entity, "state", None))

    def token_endpoint(self, context: Context):
        """
        Handle a POST request to the token endpoint.
        Args:
            context (Context): The SATOSA context.

        Returns:
            A Response object.
        """
        try:
            self._validate_request_method(context.request_method, ["POST"])
            self._validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
            self._validate_oauth_client_attestation(context)
            decoded_request = self.jws_helper.verify(context.request.body.decode("utf-8"))
            entity = self.db_engine.get_by_session_id(self._get_session_id(context))
            TokenRequest.model_validate(**decoded_request, context = {
                CONFIG_CTX: self.config_utils,
                REDIRECT_URI_CTX: entity.redirect_uri,
                CODE_CHALLENGE_METHOD_CTX: entity.code_challenge_method,
                CODE_CHALLENGE_CTX: entity.code_challenge
            })
            iat = int(time.time())
            access_token = AccessToken(
                iss=self.entity_id,
                aud=self.entity_id,
                exp=iat + self.config_utils.get_jwt_default_exp(),
                iat=iat,
                client_id=entity.client_id,
                sub=entity.client_id,
            )
            return TokenResponse.to_created_response(
                self._sign_token(access_token, "at+jwt"),
                self._sign_token(RefreshToken(**access_token.model_dump()), "rt+jwt"),
                access_token.exp,
                entity.authorization_details
            )
        except InvalidRequestException as e:
            return ResponseUtils.to_invalid_request_resp(e.message)
        except InvalidScopeException as e:
            return ResponseUtils.to_invalid_scope_resp(e.message)
        except Exception as e:
            logger.error(f"Error during invoke token endpoint: {e}")
            return ResponseUtils.to_server_error_resp("error during invoke token endpoint")


    def nonce_endpoint(self, context: Context):
        """
        Handle a POST request to the nonce endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
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
        """
        Handle a POST request to the credential endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
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
        """
        Handle a POST request to the deferred_credential endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
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
        """
        Handle a POST request to the notification endpoint.
        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object.
        """
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
    def _to_request_uri(random_part: str) -> str:
        """
        Generate the full `request_uri` from a random component.
        Args:
            random_part (str): The unique identifier to include in the URI.
        Returns:
            str: A full URN request_uri string.
        """
        return f"urn:ietf:params:oauth:request_uri:{random_part}"

    @staticmethod
    def _get_session_id(context: Context) -> str:
        """
        Extract the session ID from the SATOSA context.
        Args:
            context (Context): The SATOSA context.
        Returns:
            str: The session ID.
        """
        return context.state["SESSION_ID"]

    @staticmethod
    def _validate_content_type(content_type_header: str, accepted_content_type: str):
        """
        Validate the Content-Type header against expected value.
        Args:
            content_type_header (str): The received Content-Type header.
            accepted_content_type (str): The expected value.
        Raises:
            InvalidRequestException: If the header does not match.
        """
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
        """
        Validate that the HTTP method is allowed.
        Args:
            request_method (str): The HTTP method.
            accepted_methods (list[str]): Allowed methods.
        Raises:
            InvalidRequestException: If the method is invalid.
        """
        if request_method is None or request_method.upper() not in accepted_methods:
            logger.error(f"endpoint invoked with wrong request method: {request_method}")
            raise InvalidRequestException("invalid request method")

    @staticmethod
    def _validate_oauth_client_attestation(context: Context):
        """
        Validate that OAuth-Client-Attestation headers are present.
        Args:
            context (Context): The SATOSA context.
        Raises:
            InvalidRequestException: If required headers are missing.
        """
        if not context.http_headers["OAuth-Client-Attestation"] or not context.http_headers["OAuth-Client-Attestation-PoP"]:
            logger.error(f"Missing r{'OAuth-Client-Attestation' if not context.http_headers["OAuth-Client-Attestation"] else 'OAuth-Client-Attestation-PoP'} header for `par` endpoint")
            raise InvalidRequestException("Missing Wallet Attestation JWT header")

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
            logger.error(
                f"Error while initializing session with state {entity.state} and {entity.session_id}: {e500}"
            )
            raise e500

    def _sign_token(self, token: BaseModel, typ: str):
        jws_headers = {
            "typ": typ,
            "alg": self.config_utils.get_jwt_default_sig_alg,
        }
        return self.jws_helper.sign(
            protected=jws_headers,
            plain_dict=token.model_dump()
        )


    @property
    def db_engine(self) -> MongoStorage:
        """
        Lazily initialized access to MongoDB storage engine.
        Returns:
            MongoStorage: The initialized DB engine instance.
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
