import datetime
import json
from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any
from uuid import uuid4

from jinja2 import Template
from pydantic import ValidationError
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.models.credential_endpoint_request import CredentialEndpointRequest
from pyeudiw.openid4vci.models.openid4vci_basemodel import OpenId4VciBaseModel
from pyeudiw.openid4vci.storage.engine import OpenId4VciEngine
from pyeudiw.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.openid4vci.tools.exceptions import InvalidScopeException, InvalidRequestException
from pyeudiw.satosa.schemas.credential_specification import CredentialSpecificationConfig
from pyeudiw.satosa.schemas.metadata import (
    CredentialConfigurationFormatEnum,
    CredentialConfiguration
)
from pyeudiw.satosa.utils.session import get_session_id
from pyeudiw.satosa.utils.validation import (
    validate_request_method, validate_content_type,
    validate_oauth_client_attestation
)
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.utils.yaml_specification import yaml_load_specification_with_placeholder
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.user_storage import UserStorage
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, APPLICATION_JSON
from pyeudiw.tools.mso_mdoc import from_jwk_to_mso_mdoc_private_key, render_mso_mdoc_template
from pyeudiw.tools.utils import iat_now, exp_from_now

FIELD_TRANSFORMS = {
    "portrait": {
        "if_type": "bytes",
        "transform": "base64",
        "output": "portrait_b64"
    }
}

class BaseCredentialEndpoint(ABC, BaseEndpoint):

    def __init__(self, config: dict, internal_attributes: dict[str, dict[str, str | list[str]]], base_url: str, name: str):
        """
        Initialize the credentials endpoints class.
        Args:
            config (dict): The configuration dictionary.
            internal_attributes (dict): The internal attributes config.
            base_url (str): The base URL of the service.
            name (str): The name of the SATOSA module to append to the URL.
        """
        super().__init__(config, internal_attributes, base_url, name)
        self._metadata_jwks = self.config["metadata_jwks"]
        self.jws_helper = JWSHelper(self._metadata_jwks)
        self._mso_mdoc_private_key = from_jwk_to_mso_mdoc_private_key(self._metadata_jwks[0])
        self.db_engine = OpenId4VciEngine(config).db_engine
        self._db_user_engine = None

    def endpoint(self, context: Context) -> Response:
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            validate_oauth_client_attestation(context)
            entity = self.db_engine.get_by_session_id(get_session_id(context))
            req = self.validate_request(context, entity)
            credential_id = None
            if isinstance(req, CredentialEndpointRequest):
                credential_id = req.credential_identifier or req.credential_configuration_id
            return self.to_response(context, entity, credential_id)

        except (InvalidRequestException, InvalidScopeException, ValidationError) as e:
            return self._handle_400(context, self._handle_validate_request_error(e, "credential"), e)
        except Exception as e:
            self._log_error(
                e.__class__.__name__,
                f"Error during invoke credential endpoint: {e}"
            )
            return self._handle_500(context, "error during invoke credential endpoint", e)


    @property
    def db_user_storage_engine(self) -> UserStorage:
        """
        Lazily initialized access to MongoDB storage engine.
        Returns:q
            MongoStorage: The initialized DB engine instance.
        """
        user_storage_config = self.config["user_storage"]
        if not self._db_user_engine:
            self._db_user_engine = DBEngine(user_storage_config)

        try:
            self._db_user_engine.is_connected
        except Exception as e:
            if getattr(self, "_db_engine", None):
                self._log_error(
                    e.__class__.__name__,
                    f"OpenID4VCI db user_storage handling, connection check silently fails and get restored: {e}"
                )
            self._db_user_engine = DBEngine(user_storage_config)

        return self._db_user_engine

    @abstractmethod
    def validate_request(self, context: Context, entity: OpenId4VCIEntity) -> OpenId4VciBaseModel:
        pass

    @abstractmethod
    def to_response(self, context: Context, entity: OpenId4VCIEntity, credential_id: str | None) -> Response:
        pass

    def build_credential(self, context: Context, credential_id: str | None) -> list[str]:
        credential_list = []
        entity = self.db_engine.get_by_session_id(get_session_id(context))
        user_data = self._retrieve_user_data(entity)
        if credential_id:
            return [self._build_credential(entity, user_data, credential_id)]
        else:
            pass #todo: manage deferred

        return credential_list

    def _build_credential(self, entity: OpenId4VCIEntity, user_data: dict[str, Any], cred_key: str) -> str:
        config = self.config_utils.get_credential_configurations_supported()[cred_key]
        credential = self.specification[cred_key]
        match config.format:
            case CredentialConfigurationFormatEnum.SD_JWT.value:
                return self._issue_sd_jwt(user_data, entity, credential.template)["issuance"]
            case CredentialConfigurationFormatEnum.MSO_MDOC.value:
                return self._issue_mso_mdoc(user_data, credential, config)
            case _:
                self._log_error(
                    self.__class__.__name__,
                    f"unexpected credential_configurations_supported format {config.format}")
                raise Exception(f"Invalid credential_configurations_supported format {config.format}")

    def _issue_mso_mdoc(self, user_data: dict[str, Any], credential: CredentialSpecificationConfig, config: CredentialConfiguration) -> str:
        mdoci = MdocCborIssuer(
            private_key=self._mso_mdoc_private_key,
            alg=self._mso_mdoc_private_key['ALG']
        )
        issuance_date = datetime.date.today()
        mdoci.new(
            doctype=config.doctype,
            data=self._loader(user_data, credential.template, CredentialConfigurationFormatEnum.MSO_MDOC.value),
            validity={
                "issuance_date": issuance_date.isoformat(),
                "expiry_date": (issuance_date + timedelta(credential.expiry_days)).isoformat()
            }
        )
        return mdoci.dumps().decode()

    def _issue_sd_jwt(self, user_data: dict[str, Any] , entity: OpenId4VCIEntity, template) -> dict:
        now = iat_now()
        exp = exp_from_now(self.config_utils.get_jwt().default_exp)
        claims = {
            "iss": entity.client_id,
            "iat": now,
            "exp": exp
        }

        specification = self._loader(user_data, template, CredentialConfigurationFormatEnum.SD_JWT.value)
        specification.update(claims)
        use_decoys = specification.get("add_decoy_claims", True)

        sdjwt_at_issuer = SDJWTIssuer(
            user_claims=specification,
            issuer_keys=self._metadata_jwks,
            add_decoy_claims=use_decoys,
        )

        return {
            "jws": sdjwt_at_issuer.serialized_sd_jwt,
            "issuance": sdjwt_at_issuer.sd_jwt_issuance
        }

    def _retrieve_user_data(self, entity) ->  dict[str, Any]:
        user = self.db_user_storage_engine.get_by_fields(self._extract_lookup_identifiers(entity.attributes))
        user_data = user.model_dump()
        user_data["unique_id"] = uuid4()
        return user_data

    def _loader(self, user_data: dict, template, credential_type: str):
        match credential_type:
            case CredentialConfigurationFormatEnum.SD_JWT.value:
                template = json.dumps(
                    yaml_load_specification_with_placeholder(template)
                )
                template = Template(template)
                json_filled = template.render(**user_data)
                return json.loads(json_filled)
            case CredentialConfigurationFormatEnum.MSO_MDOC.value:
                return render_mso_mdoc_template(template, user_data, FIELD_TRANSFORMS)
            case _:
                self._log_error(self.__class__.__name__, f"unexpected template format {credential_type}")
                raise Exception(f"Invalid credential_configurations_supported format {credential_type}")

    def _extract_lookup_identifiers(self, attributes: dict):
        """
        Map user attributes to the internal lookup keys for database queries.

        Args:
            attributes (dict): The context containing user attributes.

        Returns:
            dict: A dictionary with DB lookup keys and their matched context user attributes values.
        """
        lookup_params = {}

        lookup_source = self.config_utils.get_credential_configurations().lookup_source
        ia_openid4vci = {
            attr: sources[lookup_source]
            for attr, sources in self.internal_attributes["attributes"].items()
            if lookup_source in sources
        }

        for db_field_name, possible_saml_names in ia_openid4vci.items():
            for saml_name in possible_saml_names:
                value = attributes.get(saml_name)
                if value:
                    lookup_params[db_field_name] = value[0] if isinstance(value, list) else value
                    break  # Stop at first match

        return {k: v for k, v in lookup_params.items() if v is not None}


    def _validate_configs(self):
        specification = self.config_utils.get_credential_configurations().credential_specification
        self._validate_required_configs([
            ("credential_configurations.credential_specification", specification),
            ("metadata.openid_credential_issuer.credential_configurations_supported",  self.config_utils.get_credential_configurations_supported())
        ])
        self.specification = specification
