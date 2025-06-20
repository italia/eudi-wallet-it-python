from satosa.context import Context

from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.tools.exceptions import InvalidRequestException, InvalidScopeException
from pyeudiw.satosa.utils.validation import validate_request_method, validate_content_type
from pyeudiw.status_list import array_to_bitstring
from pyeudiw.storage.user_credential_db_engine import UserCredentialEngine
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, APPLICATION_JSON


class StatusListHandler(BaseEndpoint):

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

    def endpoint(self, context: Context):
        try:
            validate_request_method(context.request_method, ["GET"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            credentials = self._db_credential_engine.get_all_sorted_by_incremental_id()
            array_to_bitstring(credentials)
        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke nonce endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke nonce endpoint", e)
