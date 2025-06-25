from enum import Enum

from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.vci_base_endpoint import VCIBaseEndpoint, GET_ACCEPTED_METHODS
from pyeudiw.openid4vci.tools.exceptions import (
    InvalidRequestException,
    InvalidScopeException
)
from pyeudiw.satosa.utils.validation import (
    validate_request_method,
    validate_content_type
)
from pyeudiw.status_list import (
    array_to_bitstring,
    encode_cwt_status_list_token
)
from pyeudiw.storage.user_credential_db_engine import UserCredentialEngine
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON,
    STATUS_LIST_JWT,
    STATUS_LIST_CWT,
    get_accept_header
)
from pyeudiw.tools.mso_mdoc import from_jwk_to_mso_mdoc_private_key
from pyeudiw.tools.utils import iat_now


class AcceptHeaderEnum(Enum):
    STATUS_LIST_JWT = STATUS_LIST_JWT
    STATUS_LIST_CWT = STATUS_LIST_CWT

_STATUS_LIST_BITS = 1

class StatusListHandler(VCIBaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the status list endpoint class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)
        self._db_credential_engine = UserCredentialEngine(config).db_credential_storage_engine
        self._metadata_jwks = self.config["metadata_jwks"]
        self.jws_helper = JWSHelper(self._metadata_jwks)
        self._mso_mdoc_private_key = from_jwk_to_mso_mdoc_private_key(self._metadata_jwks[0])


    def endpoint(self, context: Context):
        try:
            validate_request_method(context.request_method, GET_ACCEPTED_METHODS)
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            accept_header = get_accept_header(context.http_headers)
            payload = self._build_status_list_payload()
            match accept_header:
                case AcceptHeaderEnum.STATUS_LIST_JWT.value:
                    jws_headers = {
                        "typ": self._handle_header(STATUS_LIST_JWT)
                    }
                    return Response(
                        message=self.jws_helper.sign(
                            protected=jws_headers,
                            plain_dict=payload
                        ),
                        content=APPLICATION_JSON,
                    )
                case AcceptHeaderEnum.STATUS_LIST_CWT.value:
                    protected_header = {
                        16: self._handle_header(STATUS_LIST_CWT)
                    }
                    payload_parts = (protected_header, {}, payload)
                    token = encode_cwt_status_list_token(payload_parts)
                    return Response(
                        message=token.decode(),
                        content=APPLICATION_JSON,
                    )
                case _:
                    self._log_error(
                        self.__class__.__name__,
                        f"unexpected accept header {accept_header} ")
                    raise InvalidRequestException(
                        f"{'Invalid accept header' if accept_header is not None else 'Missing accept header'}")
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke status list endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke status list endpoint", e)

    @staticmethod
    def _handle_header(accepted_header: str):
        return accepted_header.removeprefix("application/")

    def _build_status_list_payload(self) -> dict:
        status_path = self.status_list.path
        status_path = status_path.lstrip("/")
        iat = iat_now()
        credentials = self._db_credential_engine.get_all_sorted_by_incremental_id()
        if not credentials or len(credentials) == 0:
            lst = ''
        else:
            bit_bytes = array_to_bitstring(credentials)
            lst = bin(int.from_bytes(bit_bytes, 'big'))[2:].zfill(len(credentials))
        return {
                "exp": iat + self.status_list.exp,
                "iat": iat,
                "status_list": {
                    "bits": _STATUS_LIST_BITS,
                    "lst": lst
                },
                "sub": f"{self._backend_url}/{status_path}/1",
                "ttl": self.status_list.ttl
            }

    def _validate_configs(self):
        cred_config = self.config_utils.get_credential_configurations()
        self._validate_required_configs([
                ("credential_configurations", cred_config),
            ])

        status_list = self.config_utils.get_credential_configurations().status_list
        self._validate_required_configs([
                ("credential_configurations.status_list", status_list),
            ])

        self._validate_required_configs([
            ("credential_configurations.status_list.path", status_list.path),
            ("credential_configurations.status_list.exp", status_list.exp),
            ("credential_configurations.status_list.ttl", status_list.ttl),
        ])

        self.status_list = status_list