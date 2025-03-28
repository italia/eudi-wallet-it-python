from typing import TypeVar
import cryptojwt.jwe.exception
import satosa.context
from pyeudiw.jwt.exceptions import JWEDecryptionError
from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.openid4vp.exceptions import (
    AuthRespParsingException,
    AuthRespValidationException,
)
from pyeudiw.openid4vp.interface import AuthorizationResponseParser
from pyeudiw.openid4vp.schemas.response import (
    AuthorizeResponseDirectPostJwt,
    AuthorizeResponsePayload,
    ResponseMode,
)
from pyeudiw.jwt.utils import decode_jwt_header


_S = TypeVar('_S', str, list[str])


def normalize_jsonstring_to_string(s: _S) -> _S:
    """
    Normalize s from string (or list of string) or JSON String (or list
    of JSON String) to simply string (or list of string).
    For example, this would map a vp_token from JSON String "ey...Ui5" to
    the naitve string ey...Ui5 (note the missing quote ").

    Note that this method is NOT intended to parse JSON String.
    For that purpose, json.loads should be preferred. Instead, this method
    should be used when an imput might be a string OR a JSON string.
    """
    if isinstance(s, str):
        return s.strip('"')
    if isinstance(s, list):
        return [v.strip('"') for v in s]
    return s


def detect_response_mode(context: satosa.context.Context) -> ResponseMode:
    """
    Try to make inference on which response mode type this is based on the
    content of an http request body
    """
    if "response" in context.request:
        return ResponseMode.direct_post_jwt
    if "vp_token" in context.request:
        return ResponseMode.direct_post
    if "error" in context.request:
        return ResponseMode.error
    raise AuthRespParsingException(
        "HTTP POST request body does not contain a recognized openid4vp response mode"
    )


def _check_http_post_headers(context: satosa.context.Context) -> None:
    """
    :raises AuthRespParsingException: if the request in the context does not \
        look like a POST request
    """
    http_method = context.request_method.upper() if context.request_method else None

    if http_method != "POST":
        err_msg = f"HTTP method [{http_method}] not supported"
        raise AuthRespParsingException(err_msg, err_msg)

    # missing header is ok; but if it's there, it must be correct
    if context.http_headers:
        content_type = context.http_headers["HTTP_CONTENT_TYPE"]
        if "application/x-www-form-urlencoded" not in content_type:
            err_msg = f"HTTP content type [{content_type}] not supported"
            raise AuthRespParsingException(err_msg, err_msg)


class DirectPostParser(AuthorizationResponseParser):
    """DirectPostParser parses authorization responses sent as body of an
    http post request.

    The reference specification is defined here
        https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-parameters
    """

    def __init__(self):
        pass

    def parse_and_validate(
        self, context: satosa.context.Context
    ) -> AuthorizeResponsePayload:
        _check_http_post_headers(context)

        resp_data: dict = context.request
        try:
            d = {}
            if (vp_token := resp_data.get("vp_token", None)):
                # vp_token should be a JSON string but caller might not be compliant and use string instead
                vp_token = normalize_jsonstring_to_string(vp_token)
                d["vp_token"] = vp_token
            if (state := resp_data.get("state", None)):
                d["state"] = state
            if (presentation_submission := resp_data["presentation_submission"]):
                d["presentation_submission"] = presentation_submission
            return AuthorizeResponsePayload(**d)
        except Exception as e:
            raise AuthRespParsingException(
                "invalid data in direct_post request body", e
            )


class DirectPostJwtJweParser(AuthorizationResponseParser):
    """DirectPostJwtJweParser parses authorization responses sent as body of an
    http post request. The parser expectes a response wrapped in a jwt; more
    precisely the managed response is x-www-form-urlencoded in the form of
    response=<jwt> where <jwt> is an **encrypted but not signed** response.
    As such, the class required a jwe helper with the correct key able to
    decrypt the jwe.

    The reference specification is defined here
        https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw
    """

    def __init__(
            self, 
            jwe_decryptor: JWEHelper, 
            enc_alg_supported: list[str] = [], 
            enc_enc_supported: list[str] = []
        ) -> None:
        self.jwe_decryptor = jwe_decryptor
        self.enc_alg_supported = enc_alg_supported
        self.enc_enc_supported = enc_enc_supported

    def parse_and_validate(
        self, context: satosa.context.Context
    ) -> AuthorizeResponsePayload:
        _check_http_post_headers(context)
        resp_data_raw: dict = context.request
        try:
            resp_data = AuthorizeResponseDirectPostJwt(**resp_data_raw)
        except Exception as e:
            raise AuthRespParsingException(
                "invalid data in direct_post.jwt request body", e
            )
        
        header = decode_jwt_header(resp_data.response)

        if not header.get("alg") in self.enc_alg_supported:
            raise AuthRespValidationException(
                "invalid data in direct_post.jwt: alg not supported"
            )
        
        if not header.get("enc") in self.enc_enc_supported:
            raise AuthRespValidationException(
                "invalid data in direct_post.jwt: enc not supported"
            )

        try:
            payload = self.jwe_decryptor.decrypt(resp_data.response)
        except JWEDecryptionError as e:
            raise AuthRespParsingException(
                "invalid data in direct_post.jwt request body: not a jwe", e
            )
        except cryptojwt.jwe.exception.DecryptionFailed:
            raise AuthRespValidationException(
                "invalid data in direct_post.jwt: unable to decrypt token"
            )
        except Exception as e:
            # unfortunately library cryptojwt is not very exhaustive on why an operation failed...
            raise AuthRespValidationException(
                "invalid data in direct_post.jwt request body", e
            )

        # iss, exp and aud MUST be OMITTED in the JWT Claims Set of the JWE
        if ("iss" in payload) or ("exp" in payload):
            raise AuthRespParsingException(
                "response token contains an unexpected lifetime claims",
                Exception("wallet mishbeahiour: JWe with bad claims"),
            )

        try:
            return AuthorizeResponsePayload(**payload)
        except Exception as e:
            raise AuthRespParsingException(
                "invalid data in the direct_post.jwt: token payload does not have the expected claims",
                e,
            )