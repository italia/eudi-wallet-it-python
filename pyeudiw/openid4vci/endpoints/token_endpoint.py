import time

from pydantic import BaseModel
from satosa.context import Context

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
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    FORM_URLENCODED
)
from pyeudiw.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.tools.validation import (
    validate_content_type,
    validate_request_method,
    validate_oauth_client_attestation
)


class TokenHandler(BaseEndpoint):

    def __init__(self, config: dict, base_url: str, name: str):
        """
        Initialize the token endpoint class.
        Args:
            config (dict): The configuration dictionary.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, base_url, name)
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])

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
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke token endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke token endpoint", e)

    def _sign_token(self, token: BaseModel, typ: str):
        jws_headers = {
            "typ": typ,
            "alg": self.config_utils.get_jwt_default_sig_alg,
        }
        return self.jws_helper.sign(
            protected=jws_headers,
            plain_dict=token.model_dump()
        )