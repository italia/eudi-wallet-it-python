from typing import Any, Callable
from urllib.parse import urlencode

from pydantic import ValidationError
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect, Response

from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import (
    VCIBaseEndpoint,
)
from pyeudiw.satosa.frontends.openid4vci.models.authorization_request import (
    PAR_REQUEST_URI_CTX,
    AuthorizationRequest,
)
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import (
    CLIENT_ID_CTX,
    ENDPOINT_CTX,
)
from pyeudiw.satosa.frontends.openid4vci.storage.engine import OpenId4VciDBEngineHandler
from pyeudiw.satosa.frontends.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.satosa.utils.session import get_session_id
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method,
)
from pyeudiw.tools.content_type import FORM_URLENCODED, HTTP_CONTENT_TYPE_HEADER

AUTHORIZATION_ENDPOINT = "authorization"


class AuthorizationHandler(VCIBaseEndpoint):

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        auth_callback: Callable[[Context, Any], Response] | None = None,
        converter: AttributeMapper | None = None,
        *args: Any,
    ):
        """
        Initialize the authorization endpoints class.

        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """

        super().__init__(
            config, internal_attributes, base_url, name, auth_callback, converter
        )
        self.db_engine = OpenId4VciDBEngineHandler(config).db_engine
        self.name = name

    def endpoint(self, context: Context) -> Response:
        """
        Handle an authorization request, via GET or POST.

        Args:
            context (Context): The SATOSA context.
        Returns:
            A Response object, usually a redirect.
        """

        entity = None
        try:
            if not context.request_method:
                self._log_error(AUTHORIZATION_ENDPOINT, "missing request method")
                raise InvalidRequestException("invalid request method")

            validate_request_method(context.request_method, ["POST", "GET"])
            if context.request_method == "POST":
                if (
                    not context.http_headers
                    or HTTP_CONTENT_TYPE_HEADER not in context.http_headers
                ):
                    self._log_error(
                        AUTHORIZATION_ENDPOINT, "missing content-type header"
                    )
                    raise InvalidRequestException("invalid content-type")

                validate_content_type(
                    context.http_headers[HTTP_CONTENT_TYPE_HEADER], FORM_URLENCODED
                )
                auth_req = self._get_body(context)
            else:
                auth_req = context.qs_params

            if not auth_req:
                raise InvalidRequestException("missing authorization request")

            req_uri = auth_req.get("request_uri", None)

            if not req_uri:
                raise InvalidRequestException(
                    "missing request_uri in authorization request"
                )

            entity = self.db_engine.search_session_by_field(
                "request_uri_part", req_uri.split(":")[-1]
            )

            if not entity:
                raise InvalidRequestException(
                    f"request_uri `{req_uri}` not found in storage"
                )

            vci_entity = OpenId4VCIEntity(**entity)

            old_session_id = vci_entity.session_id

            vci_entity.session_id = get_session_id(context)
            self.db_engine.upsert_session(old_session_id, vci_entity.model_dump())

            AuthorizationRequest.model_validate(
                auth_req,
                context={
                    ENDPOINT_CTX: AUTHORIZATION_ENDPOINT,
                    PAR_REQUEST_URI_CTX: self._to_request_uri(
                        entity["request_uri_part"]
                    ),
                    CLIENT_ID_CTX: vci_entity.client_id,
                },
            )

            if not self._auth_callback:
                raise Exception("missing auth_callback for authorization endpoint")

            internal_req = InternalData(
                subject_type="pairwise",
                requester=vci_entity.client_id,
                requester_name=None,
            )

            if not self._converter:
                raise Exception(
                    "missing attribute converter for authorization endpoint"
                )

            context.internal_data = internal_req
            context.target_backend = self.config.get(
                "default_target_authentication_backend", "openid4vp"
            )

            return self._auth_callback(context, internal_req)

        except (InvalidRequestException, ValidationError, TypeError) as e:
            self._log_error(
                e.__class__.__name__, f"Error during invoke authorization endpoint: {e}"
            )

            if entity:
                return self._to_error_redirect(
                    entity.get("redirect_uri", "") if isinstance(entity, dict) else "",
                    "invalid_request",
                    self._handle_validate_request_error(e, AUTHORIZATION_ENDPOINT),
                    entity.get("state", "") if isinstance(entity, dict) else "",
                )

            return self._handle_400(
                context,
                self._handle_validate_request_error(e, AUTHORIZATION_ENDPOINT),
                e,
            )
        except Exception as e:
            self._log_error(
                e.__class__.__name__, f"Error during invoke authorization endpoint: {e}"
            )
            if entity:
                return self._to_error_redirect(
                    entity.get("redirect_uri", "") if isinstance(entity, dict) else "",
                    "server_error",
                    "error during invoke authorization endpoint",
                    entity.get("state", "") if isinstance(entity, dict) else "",
                )

            return self._handle_500(
                context, "error during invoke authorization endpoint", e
            )

    @staticmethod
    def _to_error_redirect(url: str, error: str, desc: str, state: str):
        params = {"error": error, "error_description": desc}
        if state is not None:
            params["state"] = state
        return Redirect(f"{url}?{urlencode(params)}", content=FORM_URLENCODED)
