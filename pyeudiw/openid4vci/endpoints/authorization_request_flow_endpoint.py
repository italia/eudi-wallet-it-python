from abc import ABC, abstractmethod

from pydantic import ValidationError
from satosa.context import Context
from satosa.response import Response

from pyeudiw.openid4vci.endpoints.vci_base_endpoint import VCIBaseEndpoint
from pyeudiw.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.openid4vci.tools.exceptions import InvalidScopeException, InvalidRequestException


class BaseAuthorizationRequestFlowEndpoint(ABC, VCIBaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the authorization request flow class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)

    def endpoint(self, context: Context) -> Response:
        try:
            resp_entity = self.validate_request(context)
            if isinstance(resp_entity, OpenId4VCIEntity):
                return self.to_response(context, resp_entity)
            else:
                return resp_entity
        except (InvalidRequestException, InvalidScopeException, ValidationError) as e:
            return self._handle_400(context, self._handle_validate_request_error(e, "credential"), e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke credential endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke credential endpoint", e)


    @abstractmethod
    def validate_request(self, context: Context) -> Response | OpenId4VCIEntity:
        pass

    @abstractmethod
    def to_response(self, context: Context, entity: OpenId4VCIEntity) -> Response:
        pass
