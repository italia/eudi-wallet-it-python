import base64
from enum import Enum

from cryptojwt.jwk.jwk import key_from_jwk_dict
from pydantic import BaseModel, ValidationError
from satosa.context import Context

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.oauth2.dpop.verifier import DPoPVerifier
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import (
    POST_ACCEPTED_METHODS,
    VCIBaseEndpoint,
)
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import CONFIG_CTX, ENDPOINT_CTX
from pyeudiw.satosa.frontends.openid4vci.models.token import AccessToken, RefreshToken
from pyeudiw.satosa.frontends.openid4vci.models.token_request import (
    CODE_CHALLENGE_CTX,
    CODE_CHALLENGE_METHOD_CTX,
    REDIRECT_URI_CTX,
    SCOPE_CTX,
    TokenRequest,
)
from pyeudiw.satosa.frontends.openid4vci.models.token_response import TokenResponse
from pyeudiw.satosa.frontends.openid4vci.storage.engine import OpenId4VciDBEngineHandler
from pyeudiw.satosa.frontends.openid4vci.storage.entity import AuthorizationSession
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidScopeException
from pyeudiw.satosa.utils.validation import (
    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
    validate_content_type,
    validate_oauth_client_attestation,
    validate_oauth_client_attestation_pop,
    validate_request_method, OAUTH_CLIENT_ATTESTATION_HEADER, DPOP_HEADER
)
from pyeudiw.tools.content_type import FORM_URLENCODED, HTTP_CONTENT_TYPE_HEADER
from pyeudiw.tools.utils import iat_now


class TokenTypsEnum(Enum):
    REFRESH_TOKEN_TYP = "rt+jwt"  # nosec B105
    ACCESS_TOKEN_TYP = "at+jwt"  # nosec B105


class TokenHandler(VCIBaseEndpoint):

    _ENDPOINT_NAME = "token"

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        *args,
    ):
        """
        Initialize the token endpoint class.

        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """

        super().__init__(config, internal_attributes, base_url, name)
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])
        self.db_engine = OpenId4VciDBEngineHandler(config).db_engine
        self.federation_config = self.config.get("trust", {}).get("federation", {}).get("config", {})

    def endpoint(self, context: Context):
        """
        Handle a POST request to the token endpoint.

        Args:
            context (Context): The SATOSA context.

        Returns:
            A Response object.
        """

        try:
            validate_request_method(context.request_method, POST_ACCEPTED_METHODS)
            validate_content_type(
                context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED
            )

            if self.wallet_attestation_required:
                try:

                    header_client_attestation = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_HEADER)
                    oauth_client_attestation = validate_oauth_client_attestation(header_client_attestation,
                                                                          self.federation_config.get("authority_hints"),
                                                                          self.federation_config.get("httpc_params"),
                                                                          self.client_attestation_signing_alg_values_supported)

                    cnf_key = oauth_client_attestation.get("cnf", {}).get("jwk", {})
                    pop_attestation = context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER)
                    oauth_client_attestation_pop = validate_oauth_client_attestation_pop(pop_attestation,
                                                          cnf_key,
                                                          self.client_attestation_pop_signing_alg_values_supported)
                except InvalidRequestException as e:
                    self._log_error(
                        e.__class__.__name__,
                        f"Error during OAuth client attestation validation in `par` endpoint: {e}",
                    )
                    return self._handle_400(context, str(e), e)

            dpop_verifier = None
            if self.dpop_required:
                dpop = context.http_headers.get(DPOP_HEADER)
                if not context.http_headers or not dpop:
                    raise InvalidRequestException("Missing DPoP header")

                try:
                    dpop_verifier = DPoPVerifier(http_header_dpop=dpop)
                    if not dpop_verifier.is_valid:
                        raise InvalidRequestException("Invalid DPoP proof")
                except ValueError as e:
                    self._log_error(
                        e.__class__.__name__,
                        f"Error during DPoP validation in `token` endpoint: {e}",
                    )
                    return self._handle_400(context, str(e), e)

            data = self._get_body(context)
            if data.get("grant_type") != "authorization_code": #refresh token unsupported
                raise InvalidRequestException("Unsupported grant_type: %f".format(data.get("grant_type")))


            entity = self.db_engine.search_session_by_field("auth_code", data.get("code"))
            if not entity:
                raise InvalidRequestException("session by auth code not found")

            vci_entity = AuthorizationSession.model_validate(entity, context={
                                                                            ENDPOINT_CTX: self._ENDPOINT_NAME,
                                                                            CONFIG_CTX: self.config
                                                                        })
            if self.wallet_attestation_required:
                attestation_client_id = oauth_client_attestation.get("sub")
                if not attestation_client_id or attestation_client_id != vci_entity.client_id:
                    raise InvalidRequestException("attestation client_id mismatch")


            TokenRequest.model_validate(
                data,
                context={
                    ENDPOINT_CTX: self._ENDPOINT_NAME,
                    CONFIG_CTX: self.config,
                    REDIRECT_URI_CTX: vci_entity.redirect_uri,
                    CODE_CHALLENGE_METHOD_CTX: vci_entity.code_challenge_method,
                    CODE_CHALLENGE_CTX: vci_entity.code_challenge,
                    SCOPE_CTX: vci_entity.scope,
                },
            )
            iat = iat_now()
            authorization_details = vci_entity.authorization_details
            if authorization_details or len(authorization_details) > 0:
                for ad in authorization_details:
                    ad.credential_identifiers = [] #todo fix it

            cnf = self._build_dpop_cnf(dpop_verifier) if dpop_verifier else {}
            return TokenResponse.to_created_response(
                self._to_token(iat, vci_entity, TokenTypsEnum.ACCESS_TOKEN_TYP, cnf),
                self._to_token(iat, vci_entity, TokenTypsEnum.REFRESH_TOKEN_TYP, cnf),
                iat + self.config_utils.get_jwt().access_token_exp,
                authorization_details,
            )
        except (
            InvalidRequestException,
            InvalidScopeException,
            JWSVerificationError,
            ValidationError,
            TypeError,
        ) as e:
            return self._handle_400(
                context, self._handle_validate_request_error(e, self._ENDPOINT_NAME), e
            )
        except Exception as e:
            self._log_error(
                e.__class__.__name__, f"Error during invoke token endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke token endpoint", e)

    def _build_dpop_cnf(self, dpop_verifier: DPoPVerifier) -> dict:
        """Build cnf with jkt (RFC 9449) to bind token to DPoP key."""
        jwk = key_from_jwk_dict(dpop_verifier.public_jwk)
        thumbprint = jwk.thumbprint("SHA-256")
        jkt = base64.urlsafe_b64encode(thumbprint).rstrip(b"=").decode()
        return {"jkt": jkt}

    def _to_token(
        self, iat: int, entity: AuthorizationSession, typ: TokenTypsEnum, cnf: dict = None
    ) -> str:

        if isinstance(entity, dict):
            entity = AuthorizationSession.model_validate(entity, context={
                                                                    ENDPOINT_CTX: self._ENDPOINT_NAME,
                                                                    CONFIG_CTX: self.config
                                                                 })
        cnf = cnf or {}

        match typ:
            case TokenTypsEnum.ACCESS_TOKEN_TYP:
                exp = iat + self.config_utils.get_jwt().access_token_exp
            case TokenTypsEnum.REFRESH_TOKEN_TYP:
                exp = iat + self.config_utils.get_jwt().refresh_token_exp
            case _:
                self._log_error(
                    self.__class__.__name__, f"unexpected typ {typ} for token "
                )
                raise Exception(f"Invalid token typ {typ}")

        token = AccessToken(
            iss=self.entity_id,
            aud=self.entity_id,
            exp=exp,
            iat=iat,
            client_id=entity.client_id,
            sub=entity.client_id,
            cnf=cnf,
        )
        if typ == TokenTypsEnum.REFRESH_TOKEN_TYP:
            token = RefreshToken(**token.model_dump())

        return self._sign_token(token, typ.value)

    def _sign_token(self, token: BaseModel, typ: str) -> str:
        jws_headers = {
            "typ": typ,
        }
        return self.jws_helper.sign(
            protected=jws_headers, plain_dict=token.model_dump()
        )

    @staticmethod
    def _get_oauth_client_attestation(
        context: Context, required: bool = True
    ) -> str | None:
        """
        Retrieve oauth client attestation pop header
        """

        if (
            not context.http_headers
            or (OAUTH_CLIENT_ATTESTATION_POP_HEADER not in context.http_headers)
            or (context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER) is None)
        ):
            if required:
                raise InvalidRequestException("Missing OAuth-Client-Attestation header")
            else:
                return None
        return context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER)

    def _validate_configs(self):
        self._validate_required_configs(
            [
                ("jwt.access_token_exp", self.config_utils.get_jwt().access_token_exp),
                (
                    "jwt.refresh_token_exp",
                    self.config_utils.get_jwt().refresh_token_exp,
                ),
            ]
        )
        oauth_authorization_server = self.config_utils.get_oauth_authorization_server()
        if not oauth_authorization_server:
            self._validate_required_configs(
                [
                    ("metadata.oauth_authorization_server", oauth_authorization_server),
                ]
            )
        self._validate_required_configs(
            [
                (
                    "metadata.oauth_authorization_server.scopes_supported",
                    oauth_authorization_server.scopes_supported,
                ),
            ]
        )
