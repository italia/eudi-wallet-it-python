from satosa.context import Context
from satosa.response import Response

from pyeudiw.openid4vci.endpoints.authorization_request_flow_endpoint import BaseAuthorizationRequestFlowEndpoint
from pyeudiw.openid4vci.endpoints.vci_base_endpoint import GET_ACCEPTED_METHODS
from pyeudiw.openid4vci.storage.engine import OpenId4VciEngine
from pyeudiw.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.openid4vci.tools.exceptions import InvalidRequestException
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.satosa.utils.html_template import Jinja2TemplateHandler
from pyeudiw.satosa.utils.session import get_session_id
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method
)
from pyeudiw.tools.content_type import (
    HTTP_CONTENT_TYPE_HEADER,
    APPLICATION_JSON
)


class CredentialOfferQrCodeHandler(BaseAuthorizationRequestFlowEndpoint):
    """
    Handle a GET request to the credential_offer_qrcode endpoint.
    Args:
        context (Context): The SATOSA context.
    Returns:
        A Response object.
    """

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the Credential offer qr code endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)
        self.qrcode_template = Jinja2TemplateHandler(self.qrcode_settings["ui_template"])
        self.db_engine = OpenId4VciEngine(config).db_engine

    def validate_request(self, context: Context) -> OpenId4VCIEntity:
        validate_request_method(context.request_method, GET_ACCEPTED_METHODS)
        validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
        entity = self.db_engine.get_by_session_id(get_session_id(context))
        if entity.remote_flow_typ != RemoteFlowType.CROSS_DEVICE:
            self._log_error(
                self.__class__.__name__,
                f"Cannot use qr code, flow type {entity.remote_flow_typ} not valid!"
            )
            raise InvalidRequestException("Cannot use qr code, flow type not valid!")
        return entity

    def to_response(self, context: Context, entity: OpenId4VCIEntity) -> Response:
        result = self.qrcode_template.qrcode_page.render(
            {
                "qrcode_color": self.qrcode_settings["color"],
                "qrcode_text": entity.redirect_uri,
                "qrcode_size": self.qrcode_settings["size"],
                "qrcode_logo_path": self.qrcode_settings["logo_path"],
                "qrcode_expiration_time": self.qrcode_settings["expiration_time"],
                "state": entity.state,
                "status_endpoint": self.status_endpoint,
            }
        )
        return Response(result, content="text/html; charset=utf8", status="200")

    def _validate_configs(self):
        qrcode_settings = self.config.get("qrcode")
        self._validate_required_configs([
            ("qrcode", qrcode_settings),
        ])
        self._validate_required_configs([
            ("qrcode.size", qrcode_settings.get("size")),
            ("qrcode.color", qrcode_settings.get("color")),
            ("qrcode.expiration_time", qrcode_settings.get("expiration_time")),
            ("qrcode.logo_path", qrcode_settings.get("logo_path")),
            ("qrcode.ui_template", qrcode_settings.get("ui_template")),
        ])
        credential_configurations = self.config_utils.get_credential_configurations()
        self._validate_required_configs([
            ("credential_configurations", credential_configurations)
        ])
        self._validate_required_configs([
            ("credential_configurations.status_list", credential_configurations.status_list)
        ])
        self._validate_required_configs([
            ("credential_configurations.status_list.path", credential_configurations.status_list.path)
        ])
        self.qrcode_settings = qrcode_settings