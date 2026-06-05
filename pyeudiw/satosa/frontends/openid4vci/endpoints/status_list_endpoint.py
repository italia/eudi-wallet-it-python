from enum import Enum
import logging
import inspect
import zlib
from base64 import urlsafe_b64encode
from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import (
    GET_ACCEPTED_METHODS,
    VCIBaseEndpoint,
)
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import InvalidScopeException
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method,
)
from pyeudiw.status_list import (
    STATUS_LIST_CWT,
    STATUS_LIST_JWT,
    array_to_bitstring,
    encode_cwt_status_list_token,
    array_to_bitstring_v1
)
from pyeudiw.storage.user_credential_db_engine import UserCredentialEngine
from pyeudiw.tools.content_type import (
    APPLICATION_JSON,
    HTTP_CONTENT_TYPE_HEADER,
    HTTP_ACCEPT_HEADER,
    get_value_from_key
)
from pyeudiw.tools.mso_mdoc import from_jwk_to_mso_mdoc_private_key
from pyeudiw.tools.utils import iat_now

logger = logging.getLogger(__name__)


class AcceptHeaderEnum(Enum):
    STATUS_LIST_JWT = STATUS_LIST_JWT
    STATUS_LIST_CWT = STATUS_LIST_CWT


_STATUS_LIST_BITS = 1

_PAYLOAD_CWT_KEYS = {"exp": 6, "iat": 4, "sub": 2, "ttl": 65534}


class StatusListHandler(VCIBaseEndpoint):

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        *args,
    ):
        """
        Initialize the status list endpoint class.

        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """

        super().__init__(config, internal_attributes, base_url, name)
        _user_credential_engine = UserCredentialEngine(config)
        self._db_credential_engine = _user_credential_engine.db_credential_storage_engine
        self._metadata_jwks = self.config["metadata_jwks"]
        self.jws_helper = JWSHelper(self._metadata_jwks)
        self._mso_mdoc_private_key = from_jwk_to_mso_mdoc_private_key(
            self._metadata_jwks[0]
        )

    def endpoint(self, context: Context):
        logger.debug(f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. ")
        try:
            requested_id = context.path.split('/')[-1]
            validate_request_method(context.request_method, GET_ACCEPTED_METHODS)
            validate_content_type(
                context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON
            )
            accept_header = get_value_from_key(context.http_headers, HTTP_ACCEPT_HEADER)
            payload = self._build_status_list_payload(requested_id)
            logger.debug("Accept header: %s, Payload: %s", accept_header, payload)
            match accept_header:
                case AcceptHeaderEnum.STATUS_LIST_JWT.value:
                    jws_headers = {"typ": self._handle_header(STATUS_LIST_JWT)}
                    plain_dict = self._build_status_list_payload(requested_id)
                    plain_dict["status_list"]["lst"] = (urlsafe_b64encode(plain_dict["status_list"]["lst"]).decode("ascii").rstrip("="))
                    return Response(
                        message=self.jws_helper.sign(
                            protected=jws_headers,
                            plain_dict=plain_dict,
                        ),
                        content=APPLICATION_JSON,
                    )
                case AcceptHeaderEnum.STATUS_LIST_CWT.value:
                    lst_bytes = payload["status_list"]["lst"]
                    del payload["status_list"]
                    payload_parts = ({}, {}, payload)
                    token = encode_cwt_status_list_token(
                        payload_parts,
                        _STATUS_LIST_BITS,
                        lst_bytes,
                        _PAYLOAD_CWT_KEYS,
                        self._mso_mdoc_private_key,
                    )
                    return Response(
                        message=token.decode(),
                        content=APPLICATION_JSON,
                    )
                case _:
                    self._log_error(
                        self.__class__.__name__,
                        f"unexpected accept header {accept_header} ",
                    )
                    raise InvalidRequestException(
                        f"{'Invalid accept header' if accept_header is not None else 'Missing accept header'}"
                    )
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__, f"Error during invoke status list endpoint: {e}"
            )
            return self._handle_500(
                context, "error during invoke status list endpoint", e
            )

    @staticmethod
    def _handle_header(accepted_header: str):
        return accepted_header.removeprefix("application/")

    def _build_status_list_payload(self,status_id: str) -> dict:
        logger.debug(f"Entering method:{inspect.getframeinfo(inspect.currentframe()).function}")
        status_path = self.status_list.path.lstrip("/")
        iat = iat_now()
        credentials = self._db_credential_engine.get("get_all_sorted_by_incremental_id") or []
        bits = 1
        bit_bytes = array_to_bitstring_v1(credentials,bits=bits)
        compressed_lst = zlib.compress(bit_bytes)
        return {
            "exp": iat + self.status_list.exp,
            "iat": iat,
            "status_list": {"bits": bits,"lst": compressed_lst},
            "sub": (f"{self._backend_url}/"f"{status_path}/"f"{status_id}"
            ),
            "ttl": self.status_list.ttl,
        }

    # def _build_status_list_payload(self, status_id: str) -> dict:
    #     logger.debug(
    #         f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
    #     )
    #     print(f"Entering method: _build_status_list_payload status: {status_id}. ")
    #     bits = 1
    #     status_path = self.status_list.path
    #     print(f"status_path: {status_path}")
    #     status_path = status_path.lstrip("/")
    #     print(f"status_path: {status_path}")
    #     iat = iat_now()
    #     credentials = self._db_credential_engine.get("get_all_sorted_by_incremental_id")
    #     print(f"credentials: {credentials}")
    #     if not credentials or len(credentials) == 0:
    #         compressed_lst = ""
    #     else:
    #         bits = (len(credentials) + 7) // 8
    #         print(f"bits: {bits}")
    #         bit_bytes = array_to_bitstring(credentials)
    #         print(f"bit_bytes: {bit_bytes}")
    #         lst = bin(int.from_bytes(bit_bytes, "big"))[2:].zfill(len(credentials))
    #         print(f"lst: {lst}")
    #         byte_list = int(lst.ljust(8, '0'), 2).to_bytes((len(bit_bytes) + 7) // 8, byteorder='big')
    #         print(f"byte_list: {byte_list}")
    #         compressed_lst = zlib.compress(byte_list)
    #         print(f"compressed_lst: {compressed_lst}")
    #     return {
    #         "exp": iat + self.status_list.exp,
    #         "iat": iat,
    #         "status_list": {"bits": bits, "lst": compressed_lst},
    #         "sub": f"{self._backend_url}/{status_path}/{status_id}",
    #         "ttl": self.status_list.ttl,
    #     }

    def _validate_configs(self):
        cred_config = self.config_utils.get_credential_configurations()
        self._validate_required_configs(
            [
                ("credential_configurations", cred_config),
            ]
        )

        status_list = self.config_utils.get_credential_configurations().status_list
        self._validate_required_configs(
            [
                ("credential_configurations.status_list", status_list),
            ]
        )

        self._validate_required_configs(
            [
                ("credential_configurations.status_list.path", status_list.path),
                ("credential_configurations.status_list.exp", status_list.exp),
                ("credential_configurations.status_list.ttl", status_list.ttl),
            ]
        )

        self.status_list = status_list
