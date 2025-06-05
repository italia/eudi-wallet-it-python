import json
from abc import ABC, abstractmethod
from uuid import uuid4

from cryptojwt.jwk.ec import new_ec_key
from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vci.endpoints.base_endpoint import BaseEndpoint
from pyeudiw.openid4vci.storage.openid4vci_entity import OpenId4VCIEntity
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.user_storage import UserStorage
from pyeudiw.tools.content_type import HTTP_CONTENT_TYPE_HEADER, APPLICATION_JSON
from pyeudiw.tools.exceptions import InvalidScopeException, InvalidRequestException
from pyeudiw.tools.utils import iat_now, exp_from_now
from pyeudiw.tools.validation import validate_request_method, validate_content_type, validate_oauth_client_attestation

ALG_TO_CRV = {
    "ES256": "P-256",
    "ES384": "P-384",
    "ES512": "P-521",
}

SD_SPEC_TEMPLATE = {
    'user_claims': {
        'unique_id': '{unique_id}',
        'given_name': '{given_name}',
        'family_name': '{family_name}',
        'birthdate': '{birth_date}',
        'place_of_birth': {
            'country': '{birth_country}',
            'locality': '{birth_locality}'
        },
        'tax_id_code': '{tax_id_code}'
    },
    'holder_disclosed_claims': {
        'given_name': '{given_name}',
        'family_name': '{family_name}',
        'place_of_birth': {
            'country': '{birth_country}',
            'locality': '{birth_locality}'
        }
    },
    'key_binding': True
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
        self.jws_helper = JWSHelper(self.config["metadata_jwks"])
        self._db_user_engine = None

    def endpoint(self, context: Context) -> Response:
        try:
            validate_request_method(context.request_method, ["POST"])
            validate_content_type(context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON)
            validate_oauth_client_attestation(context)
            entity = self.db_engine.get_by_session_id(self._get_session_id(context))
            self.validate_request(context, entity)
            return self.to_response(context, entity)

        except (InvalidRequestException, InvalidScopeException) as e:
            return self._handle_400(context, e.message, e)
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
    def validate_request(self, context: Context, entity: OpenId4VCIEntity):
        pass

    @abstractmethod
    def to_response(self, context: Context, entity: OpenId4VCIEntity) -> Response:
        pass

    def issue_sd_jwt(self, context: Context) -> dict:
        now = iat_now()
        exp = exp_from_now(self.config_utils.get_jwt().default_exp)
        entity = self.db_engine.get_by_session_id(self._get_session_id(context))
        claims = {
            "iss": entity.client_id,
            "iat": now,
            "exp": exp
        }

        #todo: retrieve user data from 'handle_authn_response'
        attributes = {}
        user = self.db_user_storage_engine.get_by_fields(self._extract_lookup_identifiers(attributes))

        user_data = user.model_dump()
        user_data["unique_id"] = uuid4()
        user_data["tax_id_code"] = f"TINIT-{user.personal_administrative_number}"

        specification = self._loader(SD_SPEC_TEMPLATE, user_data)

        specification.update(claims)
        use_decoys = specification.get("add_decoy_claims", True)

        ec_alg = self.config_utils.get_jwt_default_sig_alg()
        ec_crv = ALG_TO_CRV.get(ec_alg)
        issuer_key = new_ec_key(ec_crv, alg=ec_alg)
        holder_key = new_ec_key(ec_crv, alg=ec_alg)

        #todo: handle additional_headers
        additional_headers = {'kid': issuer_key["kid"]}

        sdjwt_at_issuer = SDJWTIssuer(
            user_claims=specification,
            issuer_keys=[issuer_key],
            holder_key=holder_key,
            add_decoy_claims=use_decoys,
            extra_header_parameters=additional_headers
        )

        return {
            "jws": sdjwt_at_issuer.serialized_sd_jwt,
            "issuance": sdjwt_at_issuer.sd_jwt_issuance
        }

    @staticmethod
    def _loader(template: dict, data: dict):
        json_template = json.dumps(template)
        json_filled = json_template.format(**data)
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

        #TODO: normalize or manage different source with backend as `openid4vci`
        ia_openid4vci = {
            attr: sources['openid4vci']
            for attr, sources in self.internal_attributes["attributes"].items()
            if 'openid4vci' in sources
        }

        for db_field_name, possible_saml_names in ia_openid4vci:
            for saml_name in possible_saml_names:
                value = attributes.get(saml_name)
                if value:
                    lookup_params[db_field_name] = value[0] if isinstance(value, list) else value
                    break  # Stop at first match

        return {k: v for k, v in lookup_params.items() if v is not None}
