import datetime
import time
from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any
from uuid import uuid4

from cryptojwt.jwk.jwk import key_from_jwk_dict
from jinja2 import Template
from pydantic import ValidationError
from pymdoccbor.mdoc.issuer import MdocCborIssuer

from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.oauth2.dpop.verifier import DPoPVerifier
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.endpoints.vci_base_endpoint import (
    POST_ACCEPTED_METHODS,
    VCIBaseEndpoint,
)
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import (
    OpenId4VciBaseModel, ENDPOINT_CTX, CONFIG_CTX,
)
from pyeudiw.satosa.frontends.openid4vci.storage.engine import OpenId4VciDBEngineHandler
from pyeudiw.satosa.frontends.openid4vci.storage.entity import AuthorizationSession
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import (
    InvalidScopeException,
    MissingProofJWTException,
)
from pyeudiw.satosa.schemas.credential_specification import (
    CredentialSpecificationConfig,
)
from pyeudiw.satosa.schemas.metadata import (
    CredentialConfiguration,
    CredentialConfigurationFormatEnum,
)
from pyeudiw.satosa.utils.validation import (
    validate_content_type,
    validate_request_method, DPOP_HEADER, AUTHORIZATION_HEADER,
)
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.utils.yaml_specification import (
    yaml_load_specification,
)
from pyeudiw.storage.user_credential_db_engine import UserCredentialEngine
from pyeudiw.storage.user_entity import UserEntity
from pyeudiw.tools.content_type import APPLICATION_JSON, HTTP_CONTENT_TYPE_HEADER
from pyeudiw.tools.mso_mdoc import (
    from_jwk_to_mso_mdoc_private_key,
    render_mso_mdoc_template,
)
from pyeudiw.tools.utils import exp_from_now, iat_now, datetime_from_timestamp
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

FIELD_TRANSFORMS = {
    "portrait": {"if_type": "bytes", "transform": "base64", "output": "portrait_b64"}
}


class BaseCredentialEndpoint(ABC, VCIBaseEndpoint):

    _ENDPOINT_NAME = "credential"

    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        *args,
    ):
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
        self._mso_mdoc_private_key = from_jwk_to_mso_mdoc_private_key(
            self._metadata_jwks[0]
        )
        self.db_engine = OpenId4VciDBEngineHandler(config).db_engine
        _user_credential_engine = UserCredentialEngine(config)
        self._db_user_engine = _user_credential_engine.db_user_storage_engine
        self._db_credential_engine = (
            _user_credential_engine.db_credential_storage_engine
        )
        self._trust_evaluator = CombinedTrustEvaluator.from_config(
            self.config.get("trust", {}),
            self.db_engine,
            default_client_id=self.entity_id,
            mode=self.config.get("trust_caching_mode", "update_first"),
        )

    def endpoint(self, context: Context) -> Response:
        try:

            validate_request_method(context.request_method, POST_ACCEPTED_METHODS)
            validate_content_type(
                context.http_headers[HTTP_CONTENT_TYPE_HEADER], APPLICATION_JSON
            )

            if self.dpop_required:
                if (
                    not context.http_headers
                    or (DPOP_HEADER not in context.http_headers)
                    or (AUTHORIZATION_HEADER not in context.http_headers)
                ):
                    raise InvalidRequestException(
                        "Missing DPoP and/or Authorization header"
                    )

                dpop = context.http_headers.get(DPOP_HEADER)
                authz = context.http_headers.get(AUTHORIZATION_HEADER)
                if not dpop or not authz:
                    raise InvalidRequestException("Invalid headers")

                try:
                    dpop_verifier = DPoPVerifier(
                        http_header_dpop=dpop, http_header_authz=authz
                    )
                    if not dpop_verifier.is_valid:
                        raise InvalidRequestException("Invalid DPoP proof")
                except ValueError as e:
                    self._log_error(
                        e.__class__.__name__,
                        f"Error during DPoP validation in `token` endpoint: {e}",
                    )
                    return self._handle_400(context, str(e), e)

            auth_token = decode_jwt_payload(dpop_verifier.dpop_authz_token)
            entity = self.db_engine.search_session_by_field("access_token_jti", auth_token.get("jti"))
            auth_session = AuthorizationSession.model_validate(entity, context={
                ENDPOINT_CTX: self._ENDPOINT_NAME,
                CONFIG_CTX: self.config
            })

            data = self._get_body(context) or {}
            credential_identifier = data.get("credential_identifier") or ""
            # TODO: check/validate scope
            if data.get("credential_configuration_id"):
                credential_configuration_id = data
            else:  # validate credential_identifier with authorization_details of token
                if auth_session.authorization_details:
                    for auth_details in auth_session.authorization_details:
                        if auth_details.credential_identifiers:
                            if credential_identifier in auth_details.credential_identifiers:
                                credential_configuration_id = "_".join(credential_identifier.split("_")[:-1])
                                break
                    else:
                        raise InvalidRequestException(
                            "credential_identifier not match with token authorization_details")
                else:
                    raise InvalidRequestException("Invalid credential_configuration_id")

            self.validate_request(context, entity)

            proof_jwt = data.get("proof", {}).get("jwt") or ""
            request_header = decode_jwt_header(proof_jwt)
            request_payload = decode_jwt_payload(proof_jwt)
            client_id = request_payload.get("iss")

            #validate nonce
            self._consume_nonce(request_payload.get("nonce"))

            #validate client --> todo: move to self.validate_request
            if not (key_attestation := request_header.get("key_attestation")):
                return self._handle_400(context, "invalid key_attestation", InvalidRequestException("invalid_proof"))

            k_payload = decode_jwt_payload(key_attestation)
            for _k in k_payload.get("attested_keys") or []:
                t_print = key_from_jwk_dict(_k).thumbprint("SHA-256").decode()
                if t_print == client_id:
                    holder_key = _k
                    break
            else:
                return self._handle_400(context, "client_id mismatch", InvalidRequestException("invalid_proof"))

            return self.to_response(context, auth_session, credential_configuration_id, holder_key=holder_key)

        except (
            InvalidRequestException,
            InvalidScopeException,
            ValidationError,
            MissingProofJWTException,
        ) as e:
            return self._handle_400(
                context, self._handle_validate_request_error(e, "credential"), e
            )
        except Exception as e:
            self._log_error(
                e.__class__.__name__, f"Error during invoke credential endpoint: {e}"
            )
            return self._handle_500(
                context, "error during invoke credential endpoint", e
            )

    def _consume_nonce(self, nonce):
        if not (found_nonce := self.db_engine.get("get_nonce", nonce)):
            raise InvalidRequestException("Invalid nonce")

        now = round(time.time() * 1000)
        if found_nonce["created_at"] + found_nonce["expires_in"] <= now:
            raise InvalidRequestException("Expired nonce")

        if self.db_engine.write("consume_nonce", nonce, now) < 1:
            raise Exception("Unable to consume nonce, storage error")

    @abstractmethod
    def validate_request(self, context: Context, entity: dict) -> OpenId4VciBaseModel:
        pass

    @abstractmethod
    def to_response(
        self, context: Context, entity: AuthorizationSession, credential_id: str | None
    , **kwargs) -> Response:
        pass

    def build_credential(
        self, vci_entity: AuthorizationSession, credential_id: str | None
        , **kwargs
    ) -> list[str]:
        credential_list = []
        if not vci_entity:
            self._log_error(
                self.__class__.__name__, "No entity found for the current session."
            )
            return credential_list

        user = self._db_user_engine.get("get_by_fields",
            self._extract_lookup_identifiers(vci_entity.attributes or {})
        )
        if credential_id:
            credential_list.append(self._build_credential(user, credential_id, kwargs.get("holder_key")))
        else:
            pass  # todo: manage deferred

        return credential_list

    def _build_credential(
        self,
        user_entity: tuple[str, UserEntity],
        cred_key: str,
        holder_key: dict|None = None
    ) -> str:
        config = self.config_utils.get_credential_configurations_supported()[cred_key]
        credential = self.specification[cred_key]
        match config.format:
            case CredentialConfigurationFormatEnum.SD_JWT.value:
                return self._issue_sd_jwt(
                    user_entity, cred_type_id=cred_key, holder_key=holder_key
                )["issuance"]
            case CredentialConfigurationFormatEnum.MSO_MDOC.value:
                return self._issue_mso_mdoc(user_entity, credential, config)
            case _:
                self._log_error(
                    self.__class__.__name__,
                    f"unexpected credential_configurations_supported format {config.format}",
                )
                raise Exception(
                    f"Invalid credential_configurations_supported format {config.format}"
                )

    def _issue_mso_mdoc(
        self,
        user_entity: tuple[str, UserEntity],
        credential: CredentialSpecificationConfig,
        config: CredentialConfiguration,
    ) -> str:
        mdoci = MdocCborIssuer(
            private_key=self._mso_mdoc_private_key,
            alg=self._mso_mdoc_private_key["ALG"],
        )
        issuance_date = datetime.date.today()
        mdoci.new(
            doctype=config.doctype,
            data=self._loader(
                user_entity,
                credential.template,
                CredentialConfigurationFormatEnum.MSO_MDOC.value,
            ),
            validity={
                "issuance_date": issuance_date.isoformat(),
                "expiry_date": (
                    issuance_date + timedelta(credential.expiry_days)
                ).isoformat(),
            },
        )
        return mdoci.dumps().decode()

    def _issue_sd_jwt(
        self, user_entity: tuple[str, UserEntity], cred_type_id: str, holder_key: dict = None
    ) -> dict:
        """Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/credential-data-model.html#digital-credential-sd-jwt-metadata-attributes"""
        now = iat_now()
        exp = exp_from_now(self.config_utils.get_jwt().default_exp) # TODO check date_of_expiry
        cred_config: 'CredentialConfigurationsConfig' = self.config_utils.get_credential_configurations()
        iss_cred_supp_conf = self.config_utils.get_credential_configurations_supported()[cred_type_id] # TODO: verify algorithms and claims with the supported ones
        cred_specification: 'CredentialSpecificationConfig' = cred_config.credential_specification[cred_type_id]
        required_claims = {"iss": self.entity_id, "exp": exp, "issuing_authority": cred_config.issuing_authority,
                           "issuing_country": cred_config.issuing_country, "vct": iss_cred_supp_conf.vct}
        user_id, _ = user_entity # TODO: Generalize for issuing credentials other than PID
        supported_optional_claims = {"sub": str(uuid4()), "iat": now, "nbf": now + cred_config.nbf_delta,
            "issuance_date": datetime_from_timestamp(now).strftime('%Y-%m-%dT%H:%M:%SZ'), #ISO 8601
            "date_of_expiry": (datetime_from_timestamp(now) + timedelta(cred_specification.expiry_days)).strftime('%Y-%m-%dT%H:%M:%SZ'), #ISO 8601
            "status": self._build_status_list_payload(user_id),
            "trust_framework": cred_specification.trust_framework,
            "assurance_level": cred_specification.assurance_level,
            "vct#integrity": "..."} # TODO: generate it
        specification = self._loader(
            user_entity, cred_specification.template, CredentialConfigurationFormatEnum.SD_JWT.value, extra_claims=supported_optional_claims
        )
        use_decoys = specification.get("add_decoy_claims", True)

        sdjwt_at_issuer = SDJWTIssuer(
            user_claims=required_claims | (specification.get("user_claims" ) or {}), holder_key=holder_key,
            issuer_keys=self._metadata_jwks,
            add_decoy_claims=use_decoys,
            extra_header_parameters=self._trust_evaluator.get_jwt_header_trust_parameters(
                issuer=self.entity_id
            ),
        )

        return {
            "jws": sdjwt_at_issuer.serialized_sd_jwt,
            "issuance": sdjwt_at_issuer.sd_jwt_issuance,
        }

    @staticmethod
    def _retrieve_user_data(
        user_entity: tuple[str, UserEntity] | UserEntity,
    ) -> dict[str, Any]:
        if isinstance(user_entity, UserEntity):
            user = user_entity
        else:
            _, user = user_entity

        user_data = user.model_dump()
        user_data["unique_id"] = uuid4()
        return user_data

    def _loader(
        self, user_entity: tuple[str, UserEntity], template, credential_type: str
        , extra_claims: dict = None) -> dict:
        user_id, user_data = user_entity
        match credential_type:
            case CredentialConfigurationFormatEnum.SD_JWT.value:
                template = Template(template)
                user_data = self._retrieve_user_data(user_data)
                user_data = user_data | (extra_claims or {})
                json_filled = template.render(**user_data)
                return yaml_load_specification(json_filled)
            case CredentialConfigurationFormatEnum.MSO_MDOC.value:
                data = render_mso_mdoc_template(
                    template, user_data.model_dump(), FIELD_TRANSFORMS
                )
                data["status"] = self._build_status_list_payload(user_id)
                return data
            case _:
                self._log_error(
                    self.__class__.__name__,
                    f"unexpected template format {credential_type}",
                )
                raise Exception(
                    f"Invalid credential_configurations_supported format {credential_type}"
                )

    def _build_status_list_payload(self, user_id: str):
        # credential = self._db_credential_engine.get("get_credential_by_user_id", user_id) # todo: store credential
        return {
            "status_list": {
                "idx": "credential.incremental_id",
                "uri": f"{self.status_endpoint}/{"credential.incremental_id"}",
            }
        }

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
                    lookup_params[db_field_name] = (
                        value[0] if isinstance(value, list) else value
                    )
                    break  # Stop at first match

        return {k: v for k, v in lookup_params.items() if v is not None}

    def _validate_configs(self):
        credential_config = self.config_utils.get_credential_configurations()
        self._validate_required_configs(
            [
                ("credential_configurations", credential_config),
            ]
        )

        specification = credential_config.credential_specification
        self._validate_required_configs(
            [
                ("credential_configurations.credential_specification", specification),
                (
                    "metadata.openid_credential_issuer.credential_configurations_supported",
                    self.config_utils.get_credential_configurations_supported(),
                ),
            ]
        )

        status_list = credential_config.status_list
        self._validate_required_configs(
            [
                ("credential_configurations.status_list", status_list),
            ]
        )

        self._validate_required_configs(
            [
                (
                    "credential_configurations.status_list.path",
                    credential_config.status_list.path,
                )
            ]
        )

        self.specification = specification
