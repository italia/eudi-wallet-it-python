import json
from abc import ABC, abstractmethod
import datetime
from datetime import timedelta
from typing import Any
from uuid import uuid4

import cbor2
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
from pyeudiw.satosa.schemas.metadata import CredentialConfigurationFormatEnum, CredentialConfiguration
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
from pyeudiw.tools.mso_mdoc import from_jwk_to_mso_mdoc_private_key
from pyeudiw.tools.utils import iat_now, exp_from_now

DATA = {
    "org.iso.18013.5.1": {
        "expiry_date": "2024-02-22",
        "issue_date": "2023-11-14",
        "issuing_country": "IT",
        "issuing_authority": "Gli amici della Salaria",
        "family_name": "Rossi",
        "given_name": "Mario",
        "birth_date": "1956-01-12",
        "document_number": "XX1234567",
        "portrait": b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x90\x00\x90\x00\x00\xff\xdb\x00C\x00\x13\r\x0e\x11\x0e\x0c\x13\x11\x0f\x11\x15\x14\x13\x17\x1d0\x1f\x1d\x1a\x1a\x1d:*,#0E=IGD=CALVm]LQhRAC_\x82`hqu{|{J\\\x86\x90\x85w\x8fmx{v\xff\xdb\x00C\x01\x14\x15\x15\x1d\x19\x1d8\x1f\x1f8vOCOvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\xff\xc0\x00\x11\x08\x00\x18\x00d\x03\x01"\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x1b\x00\x00\x03\x01\x00\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x06\x04\x01\x02\x03\x07\xff\xc4\x002\x10\x00\x01\x03\x03\x03\x02\x05\x02\x03\t\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x00\x05\x11\x06\x12!\x131\x14\x15Qaq"A\x07\x81\xa1\x165BRs\x91\xb2\xc1\xf1\xff\xc4\x00\x15\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xc4\x00\x1a\x11\x01\x01\x01\x00\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01A\x11!1a\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00\xa5\xbb\xde"\xda#)\xc7\xd6\x92\xbc}\r\x03\xf5,\xfb\x0f\xf7^z~\xf3\xe7p\x97#\xa1\xd0\xda\xe1F\xdd\xfb\xb3\xc09\xce\x07\xad+\xd4z~2\xdb\xb8\xdd\x1dR\xd6\xefK(Od\xa4\x80\x06}\xfbQ\xf8\x7f\xfb\x95\xff\x00\xeb\x9f\xf1M!]\xe6j\xf0\x89\xceD\xb7\xdb\xde\x9c\xb6\x89\n(8\xed\xdf\x18\x07\x8fz\xddb\xd4\x11\xefM\xb9\xb1\ne\xd6\xb9Z\x14s\x81\xea\rI[\x932u\xfek\xbau\xc1\x14\x10J\x8b\xa4\x10A>\x98=\xff\x00OZ\xf5\xd3KKL\xdec-\x0b\xf1\xfd\x15\x92\xbd\xd9\x1cd\x11\xf3\x93L/\xa6\xafkT\x97]\x10m\xcfJe\xaeV\xe8V\x00\x1e\xbc\x03\xc7\xce)\xdd\x9e\xef\x1e\xf1\x0f\xc4G\xdc\x9d\xa7j\xd2\xae\xe957\xa1\xba~Op\xdd\x8e\xff\x00W\xc6\xdf\xfb^\x1a\x19\x85J\x83u\x8eTR\x87P\x94n\xc6pHP\xcd\x03{\xce\xb0\x8bm},\xc7m3\x17\xfc{\\\xc0O\xb6pri\xc5\xc6\xe0\xc5\xb6\n\xe5I$!#\xb0\xe4\x93\xf6\x02\xa0uU\x9e5\x99p\xd9\x8d\xb8\x95%EkQ\xc9Q\xc8\xaf\xa1>\xa8\xe9\x8e<Yh6x=\\c\xf5\xa6\x1a\x99\xfd\xb7)\x08u\xdbK\xe8\x8a\xb3\x84\xbb\xbb\xbf\xc7\x18?\xde\xaac>\x89Q\xdb}\xa3\x96\xdcHRO\xb1\xa8\xbda\x1aZ\xa2\xa2C/0\xabB\nzm2@\xc7\x18\xcf\x03\x1f\xa9\xefL\x9a\xd5P Z\xa0)Q\xdfJ\x1dl\x84!\xb0\x15\xb7i\xdb\x8c\x92)\x83~\xa2\xbe\x8b\x1b\r9\xd0\xeb\xa9\xc5\x14\x84\xef\xdb\x8c\x0e\xfd\x8d%\x8d\xaf<D\x96\x99\xf2\xed\xbdE\x84\xe7\xaf\x9cd\xe3\xf9k\x9b\xeb(\xd4\xac@\x93\x1edx\xc8\xe7j$\xa8%D\x95\x01\xd8g\xd2\xb1\xdc\xde\xba\xe9\x9b\x9cu*\xe4\xec\xd6\xdd\xe4\xa1y\xc1\xc1\xe4`\x93\x8f\x91I\xefe^Q\\\x03\x91\x9a(\x9c\xb3\xdc\xa2x\xfb{\xf1w\xf4\xfa\xa8)\xdd\x8c\xe3\xf2\xac\x9a~\xcd\xe4\x90\x97\x1f\xaf\xd7\xdc\xe1^\xed\x9bq\xc0\x18\xc6O\xa5\x14QK$\xe8\xe4\xf8\xc5\xc9\xb7\\\x1e\x82W\x9d\xc1#=\xfe\xc0\x828\xf6\xad\xd6-9\x1a\xcc\x1cRV\xa7\x9epmR\xd41\xc7\xa0\x14Q@\xb9\xfd\x14\x9e\xb3\xa6\r\xc5\xe8\x8c\xbb\xc2\xda\t$\x11\xe9\xdcq\xf3\x9awf\xb4G\xb3D\xe8G\xdc\xac\x9d\xcbZ\xbb\xa8\xd1E\x06\x1dC\xa6\xfc\xf1\xe6\\\xf1]\x0e\x90#\x1d=\xd9\xcf\xe6)\x95\xc6\xdc\xc5\xca\x12\xa2\xc9\x04\xa1_q\xdd\'\xd4QE>\t\xd1\xa2\x14P\x96\x1c\xbb>\xa8\xa9VC;x\x1f\x1c\xe3=\xfe\xd5O\x0e+P\xa2\xb7\x1d\x84\xedm\xb1\x80(\xa2\x81u\xf7O\xc6\xbd\xa1\x05\xc5)\xa7\x91\xc2\\O<z\x11\xf7\x15\x86&\x8fJf\xb7&\xe3=\xe9\xeao\x1bR\xb1\x81\xc7`rNG\xb5\x14R\nZ(\xa2\x83\xff\xd9',
        "driving_privileges": [
            {
                "vehicle_category_code": "A",
                "issue_date": cbor2.CBORTag(
                    1004,
                    value=cbor2.dumps(
                        "2020-09-17"
                    )
                ),
                "expiry_date": cbor2.CBORTag(
                    1004,
                    value=cbor2.dumps(
                        "2031-06-10"
                    )
                )
            }
        ],
        "un_distinguishing_sign": "I"
    },
    "org.iso.18013.5.1.it": {
        "verification.evidence": {
            "organization_name": "Motorizzazione Civile",
            "organization_id":  "m_inf",
            "country_code": "it",
        },
        "verification.trust_framework": "eidas",
        "verification.assurance_level": "high"
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
        self.db_engine = OpenId4VciEngine.db_engine
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
        if credential_id:
            return [self._build_credential(entity, credential_id)]
        else:
            pass #todo: manage deferred

        return credential_list

    def _build_credential(self, entity: OpenId4VCIEntity, cred_key: str) -> str:
        config = self.config_utils.get_credential_configurations_supported()[cred_key]
        credential = self.specification[cred_key]
        user_data = self._retrieve_user_data(entity)
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
            data=self._loader(user_data, credential.template), #TODO: handle template for mso_mdoc
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

        specification = self._loader(user_data, template)
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

    @staticmethod
    def _loader(data: dict, template):
        template = json.dumps(
            yaml_load_specification_with_placeholder(template)
        )
        template = Template(template)
        json_filled = template.render(**data)
        return json.loads(json_filled)

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
