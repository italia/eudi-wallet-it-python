from dataclasses import dataclass
import json
import satosa.context

from pyeudiw.jwk.exceptions import KidNotFoundError
from pyeudiw.jwt.exceptions import JWEDecryptionError
from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
import cryptojwt.jwe.exception

from pyeudiw.openid4vp.exceptions import AuthRespParsingException, AuthRespValidationException
from pyeudiw.openid4vp.interface import AuthorizationResponseParser
from pyeudiw.openid4vp.schemas.response import AuthorizeResponseDirectPostJwt, AuthorizeResponsePayload


def _check_http_post_headers(context: satosa.context.Context):
    if (http_method := context.request_method.upper()) != "POST":
        raise AuthRespParsingException(f"HTTP method [{http_method}] not supported")

    if (content_type := context.http_headers['HTTP_CONTENT_TYPE']) != "application/x-www-form-urlencoded":
        raise AuthRespParsingException(f"HTTP content type [{content_type}] not supported")


class DirectPostParser(AuthorizationResponseParser):
    """TODO: docsting
    """

    def __init__(self):
        pass

    def parse_and_validate(self, context: satosa.context.Context) -> AuthorizeResponsePayload:
        _check_http_post_headers(context)

        resp_data: dict = context.request
        try:
            return AuthorizeResponsePayload(**resp_data)
        except Exception as e:
            raise AuthRespParsingException("invalid data in direct_post request body", e)


class DirectPostJwtParser(AuthorizationResponseParser):
    """TODO: docstring
    """

    def __init__(self, jwe_decryptor: JWEHelper):
        self.jwe_decryptor = jwe_decryptor
        pass

    def parse_and_validate(self, context: satosa.context.Context) -> AuthorizeResponsePayload:
        _check_http_post_headers(context)
        resp_data_raw: dict = context.request
        try:
            resp_data = AuthorizeResponseDirectPostJwt(**resp_data_raw)
        except Exception as e:
            raise AuthRespParsingException("invalid data in direct_post.jwt request body", e)
        try:
            payload = self.jwe_decryptor.decrypt(resp_data.response)
        except JWEDecryptionError as e:
            raise AuthRespParsingException("invalid data in direct_post.jwt request body: not a jwe", e)
        except cryptojwt.jwe.exception.DecryptionFailed:
            raise AuthRespValidationException("invalid data in direct_post.jwt: unable to decrypt token")
        except Exception as e:
            raise AuthRespParsingException("invalid data in direct_post.jwt request body", e)
        try:
            return AuthorizeResponsePayload(**payload)
        except Exception as e:
            raise AuthRespParsingException("invalid data in the direct_post.jwt: token payload does not have the expected claims", e)


def _get_jwk_kid_from_store(jwt: str, key_store: dict[str, dict]) -> dict:
    headers = decode_jwt_header(jwt)
    kid: str | None = headers.get("kid", None)
    if kid is None:
        raise KidNotFoundError("authorization response is missing mandatory parameter [kid] in header section")
    jwk_dict = key_store.get(kid, None)
    if jwk_dict is None:
        raise KidNotFoundError(f"authorization response is encrypted with jwk with kid='{kid}' not found in store")
    return jwk_dict


def _decrypt_jwe(jwe: str, decrypting_jwk: dict[str, any]) -> dict:
    decrypter = JWEHelper(decrypting_jwk)
    return decrypter.decrypt(jwe)


def _verify_and_decode_jwt(jwt: str, verifying_jwk: dict[dict, ECKey | RSAKey | dict]) -> dict:
    verifier = JWSHelper(verifying_jwk)
    raw_payload: str = verifier.verify(jwt)["msg"]
    payload: dict = json.loads(raw_payload)
    return payload
