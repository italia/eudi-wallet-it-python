from enum import Enum

from pydantic import (
    BaseModel,
    ValidationError
)
from satosa.context import Context

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.models.openid4vci_basemodel import CONFIG_CTX
from pyeudiw.openid4vci.models.token import (
    AccessToken,
    RefreshToken
)
from pyeudiw.openid4vci.models.token_request import (
    TokenRequest,
    REDIRECT_URI_CTX,
    CODE_CHALLENGE_CTX,
    CODE_CHALLENGE_METHOD_CTX
)
from pyeudiw.openid4vci.models.token_response import TokenResponse
from pyeudiw.openid4vci.storage.openid4vci_engine import OpenId4VciEngine
from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from pyeudiw.satosa.utils.session import get_session_id
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method,
    validate_oauth_client_attestation,
    OAUTH_CLIENT_ATTESTATION_POP_HEADER
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    FORM_URLENCODED
)
from pyeudiw.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.tools.utils import iat_now


class TokenTypsEnum(Enum):
    REFRESH_TOKEN_TYP = "rt+jwt" #nosec B105
    ACCESS_TOKEN_TYP = "at+jwt" #nosec B105

class TokenHandler(BaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
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
        self.db_engine = OpenId4VciEngine.db_engine

    def endpoint(self, context: Context):
        """
        Handle a POST request to the token endpoint.
        Args:
            context (Context): The SATOSA context.

        Returns:
            A Response object.
        """
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED)
            validate_oauth_client_attestation(context)
            self.jws_helper.verify(self._get_oauth_client_attestation(context))
            entity = self.db_engine.get_by_session_id(get_session_id(context))
            TokenRequest.model_validate(self._get_body(context), context = {
                CONFIG_CTX: self.config,
                REDIRECT_URI_CTX: entity.redirect_uri,
                CODE_CHALLENGE_METHOD_CTX: entity.code_challenge_method,
                CODE_CHALLENGE_CTX: entity.code_challenge
            })
            iat = iat_now()
            return TokenResponse.to_created_response(
                self._to_token(iat, entity, TokenTypsEnum.ACCESS_TOKEN_TYP),
                self._to_token(iat, entity, TokenTypsEnum.REFRESH_TOKEN_TYP),
                iat + self.config_utils.get_jwt().access_token_exp,
                entity.authorization_details
            )
        except (InvalidRequestException, InvalidScopeException, JWSVerificationError, ValidationError, TypeError) as e:
            return self._handle_400(context, self._handle_validate_request_error(e, "token"), e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke token endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke token endpoint", e)

    def _to_token(self, iat: int, entity: OpenId4VCIEntity, typ: TokenTypsEnum) -> str:
        match typ:
          case TokenTypsEnum.ACCESS_TOKEN_TYP:
            exp = iat + self.config_utils.get_jwt().access_token_exp
          case TokenTypsEnum.REFRESH_TOKEN_TYP:
            exp = iat + self.config_utils.get_jwt().refresh_token_exp
          case _:
            self._log_error(
                self.__class__.__name__,
                            f"unexpected typ {typ} for token ")
            raise Exception(f"Invalid token typ {typ}")
        token = AccessToken(
            iss=self.entity_id,
            aud=self.entity_id,
            exp=exp,
            iat=iat,
            client_id=entity.client_id,
            sub=entity.client_id,
        )
        if typ == TokenTypsEnum.REFRESH_TOKEN_TYP:
            token = RefreshToken(**token.model_dump())

        return self._sign_token(token, typ.value)


    def _sign_token(self, token: BaseModel, typ: str) -> str:
        jws_headers = {
            "typ": typ,
        }
        return self.jws_helper.sign(
            protected=jws_headers,
            plain_dict=token.model_dump()
        )

    @staticmethod
    def _get_oauth_client_attestation(context: Context):
        """
          Retrieve oauth client attestation pop header
        """
        if not context.http_headers:
            return None
        return context.http_headers.get(OAUTH_CLIENT_ATTESTATION_POP_HEADER)