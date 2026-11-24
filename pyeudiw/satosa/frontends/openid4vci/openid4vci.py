"""
The OpenID4vci (Credential Issuer) frontend module for the satosa proxy
"""

import logging
from typing import Callable

from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import ENDPOINT_CTX, CONFIG_CTX
from satosa.context import Context
from satosa.frontends.base import FrontendModule
from satosa.internal import InternalData
from satosa.response import Response

from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.models.authorization_response import (
    AuthorizationResponse,
)
from pyeudiw.satosa.frontends.openid4vci.storage.engine import OpenId4VciDBEngineHandler
from pyeudiw.satosa.frontends.openid4vci.storage.entity import AuthorizationSession
from pyeudiw.satosa.utils.session import get_session_id
from pyeudiw.tools.endpoints_loader import EndpointsLoader

logger = logging.getLogger(__name__)


class OpenID4VCIFrontend(FrontendModule):
    """
    OpenID Connect frontend module based on satosa.
    """
    _CTX = "OpenID4VCI_frontend" #todo It is only used for logging trace, maybe it can be removed

    def __init__(
        self,
        auth_req_callback_func: Callable[[Context, InternalData], Response],
        internal_attributes: dict[str, dict[str, str | list[str]]],
        config: dict[str, dict[str, str] | list[str]],
        base_url: str,
        name: str,
    ):
        FrontendModule.__init__(
            self, auth_req_callback_func, internal_attributes, base_url, name
        )
        self.internal_attributes = internal_attributes
        self.config = config
        self.base_url = base_url
        self.name = name
        self.db_engine = OpenId4VciDBEngineHandler(config).db_engine

    def register_endpoints(self, backend_names, **kwargs):
        """
        See super class satosa.frontends.base.FrontendModule

        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """

        el = EndpointsLoader(
            config=self.config,
            internal_attributes=self.internal_attributes,
            base_url=self.base_url,
            name=self.name,
            auth_callback_func=self.auth_req_callback_func,
            converter=self.converter,
        )
        url_map = []
        for path, inst in el.endpoint_instances.items():
            url_map.append((f"{self.name}/{path}", inst))
            # OpenID4VCI / RFC 8414 path insertion: /.well-known/{resource}/{name}
            if path.startswith(".well-known/"):
                url_map.append((f"{path}/{self.name}", inst))

        logger.debug(f"Loaded OpenID4VCI endpoints: {url_map}")
        return url_map

    def handle_authn_response(self, context: Context, internal_resp: InternalData):
        """
        Handle the authentication response from the backend.

        Args:
            context (Context): The SATOSA context.
            internal_resp (InternalData): The internal response from the backend.
        Returns:
            A Response object.
        """

        try:
            session_id = get_session_id(context)
            vci_document_id = None
            if context.state:
                vci_document_id = context.state.get("openid4vci_document_id")

            entity = None
            if vci_document_id:
                try:
                    entity = self.db_engine.get_by_id(vci_document_id)
                except Exception:
                    entity = None
            if not entity:
                entity = self.db_engine.get_pending_openid4vci_by_session_id(session_id)

            if not entity:
                logger.error(f"Session with ID {session_id} not found in storage")
                raise InvalidRequestException(
                    f"Session with ID {session_id} not found in storage"
                )

            auth_session = AuthorizationSession.model_validate(entity, context={
                                                                            ENDPOINT_CTX: self._CTX,
                                                                            CONFIG_CTX: self.config
                                                                        })
            if auth_session.abandoned or (
                auth_session.finalized and auth_session.auth_code
            ):
                raise InvalidRequestException(
                    f"Session with document_id {auth_session.document_id} is abandoned or already finalized"
                )

            auth_session.attributes = internal_resp.attributes
            response = AuthorizationResponse(
                state=auth_session.state,
                iss=self.config.get("metadata", {})
                .get("openid_credential_issuer", {})
                .get("credential_issuer") or f"{self.base_url}/{self.name}"
            )

            auth_session.auth_code = response.code
            auth_session.finalized = True
            auth_session.abandoned = False
            self.db_engine.upsert_session_by_document_id(
                auth_session.document_id, auth_session.model_dump()
            )
            return response.to_redirect_response(auth_session.redirect_uri)

        except InvalidRequestException as e:
            logger.error(f"Invalid request: {e}")
            return Response(status="400", message=str(e))
        except Exception as e:
            logger.error(f"Error handling authentication response: {e}")
            return Response(status="500", message="Internal Server Error")
