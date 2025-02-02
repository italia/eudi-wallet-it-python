import json
import logging
from datetime import datetime
from typing import Any, Callable, List, Union

import satosa
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import RSAKey
from satosa.context import Context
from satosa.response import Response

from pyeudiw.federation.exceptions import (ProtocolMetadataNotFound,
                                           TimeValidationError)
from pyeudiw.federation.policy import TrustChainPolicy, combine
from pyeudiw.federation.statements import (EntityStatement,
                                           get_entity_configurations)
from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.jwk import JWK
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload, is_jwt_format
from pyeudiw.satosa.exceptions import DiscoveryFailedError
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.trust.exceptions import (InvalidAnchor, InvalidTrustType,
                                      MissingProtocolSpecificJwks,
                                      MissingTrustType, UnknownTrustAnchor)
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.x509.verify import (get_issuer_from_x5c, is_der_format,
                                 verify_x509_anchor)

from .commons import DEFAULT_HTTPC_PARAMS

logger = logging.getLogger(__name__)


_ISSUER_METADATA_TYPE = "openid_credential_issuer"


class FederationHandler(TrustHandlerInterface, BaseLogger):
    def __init__(
        self,
        metadata: List[dict],
        authority_hints: List[str],
        trust_anchors: List[str],
        default_sig_alg: str,
        federation_jwks: List[dict[str, Union[str, List[str]]]],
        trust_marks: List[dict],
        federation_entity_metadata: dict[str, str],
        client_id: str,
        entity_configuration_exp: int = 800,
        httpc_params: dict = DEFAULT_HTTPC_PARAMS,
        cache_ttl: int = 0,
        metadata_type: str = _ISSUER_METADATA_TYPE,
        **kwargs
    ):

        self.httpc_params = httpc_params
        self.cache_ttl = cache_ttl
        # TODO - this MUST be handled in httpc_params ...
        self.http_async_calls = False
        self.client_id = client_id

        self.metadata_type = metadata_type
        self.metadata: dict = metadata
        self.authority_hints: List[str] = authority_hints
        self.trust_anchors: List[str] = trust_anchors
        self.default_sig_alg: str = default_sig_alg
        self.federation_jwks: List[dict[str,
                                        Union[str, List[str]]]] = federation_jwks
        self.trust_marks: List[dict] = trust_marks
        self.federation_entity_metadata: dict[str,
                                              str] = federation_entity_metadata
        self.client_id: str = federation_entity_metadata
        self.entity_configuration_exp = entity_configuration_exp

        self.federation_public_jwks = [
            JWK(i).as_public_dict() for i in self.federation_jwks
        ]

        for k, v in kwargs.items():
            if not hasattr(self, k):
                logger.warning(
                    f"Trust - FederationHandler. {k} was provided in the init but not handled."
                )

    def extract_and_update_trust_materials(self, issuer, trust_source):
        return trust_source

    def get_metadata(self, issuer, trust_source):
        return trust_source

    @property
    def entity_configuration(self) -> dict:
        """Returns the entity configuration as a JWT."""
        data = self.entity_configuration_as_dict
        _jwk = self.federation_jwks[0]
        jwshelper = JWSHelper(_jwk)
        return jwshelper.sign(
            protected={
                "alg": self.default_sig_alg,
                "kid": _jwk["kid"],
                "typ": "entity-statement+jwt"
            },
            plain_dict=data
        )

    @property
    def entity_configuration_as_dict(self) -> dict:
        """Returns the entity configuration as a dictionary."""
        ec_payload = {
            "exp": exp_from_now(minutes=self.entity_configuration_exp),
            "iat": iat_now(),
            "iss": self.client_id,
            "sub": self.client_id,
            "jwks": {
                "keys": self.federation_public_jwks
            },
            "metadata": {
                self.metadata_type: self.metadata,
                "federation_entity": self.federation_entity_metadata
            },
            "authority_hints": self.authority_hints
        }
        return ec_payload

    def entity_configuration_endpoint(self, context: satosa.context.Context) -> satosa.response.Response:
        """
        Entity Configuration endpoint.

        :param context: The current context
        :type context: Context

        :return: The entity configuration
        :rtype: Response
        """

        if context.qs_params.get('format', '') == 'json':
            return Response(
                json.dumps(self.entity_configuration_as_dict),
                status="200",
                content="application/json"
            )

        return satosa.response.Response(
            self.entity_configuration,
            status="200",
            content="application/entity-statement+jwt"
        )

    def build_metadata_endpoints(self, backend_name: str, entity_uri: str) -> list[tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]]:

        metadata_path = f'^{backend_name.strip("/")}/.well-known/openid-federation$'
        response_json = self.entity_configuration_as_dict

        def metadata_response_fn(ctx: satosa.context.Context, *args) -> satosa.response.Response:
            return JsonResponse(message=response_json)
        return [(metadata_path, metadata_response_fn)]

    def get_backend_trust_chain(self) -> list[str]:
        """
        Get the backend trust chain. In case something raises an Exception (e.g. faulty storage), logs a warning message
        and returns an empty list.

        :return: The trust chain
        :rtype: list
        """

        try:
            trust_evaluation_helper = self.build_trust_chain_for_entity_id(
                storage=self.db_engine,
                entity_id=self.client_id,
                entity_configuration=self.entity_configuration,
                httpc_params=self.httpc_params
            )
            self.db_engine.add_or_update_trust_attestation(
                entity_id=self.client_id,
                attestation=trust_evaluation_helper.trust_chain,
                exp=trust_evaluation_helper.exp
            )
            return trust_evaluation_helper.trust_chain

        except (DiscoveryFailedError, EntryNotFound, Exception) as e:
            message = (
                f"Error while building trust chain for client with id: {self.client_id}. "
                f"{e.__class__.__name__}: {e}"
            )
            self._log_warning("Trust Chain", message)

        return []

# TRIANGE - TODO - CLEANUP

    def init_trust_resources(self) -> None:
        """
        Initializes the trust resources.
        """
        # TODO: adapt method to init ALL types of trust resources (if configured)

        # private keys by kid
        self.federations_jwks_by_kids = {
            i['kid']: i for i in self.config['trust']['federation']['config']['federation_jwks']
        }
        # dumps public jwks
        self.federation_public_jwks = [
            JWK(i).public_key for i in self.config['trust']['federation']['config']['federation_jwks']
        ]
        # we close the connection in this constructor since it must be fork safe and
        # get reinitialized later on, within each fork
        self.update_trust_anchors()

        try:
            self.get_backend_trust_chain()
        except Exception as e:
            self._log_critical(
                "Backend Trust",
                f"Cannot fetch the trust anchor configuration: {e}"
            )

        # the engine will be initialized later on
        self.db_engine.close()
        self._db_engine = None

    def update_trust_anchors(self):
        """
        Updates the trust anchors of current instance.
        """

        tas = self.config['trust']['federation']['config']['trust_anchors']
        self._log_info("Trust Anchors updates", f"Trying to update: {tas}")

        for ta in tas:
            try:
                self.update_trust_anchors_ecs(
                    db=self.db_engine,
                    trust_anchors=[ta],
                    httpc_params=self.config['network']['httpc_params']
                )
            except Exception as e:
                self._log_warning("Trust Anchor updates",
                                  f"{ta} update failed: {e}")

            self._log_info("Trust Anchor updates", f"{ta} updated")

    #  def _validate_trust(self, context: Context, jws: str):
        #  """
        #  Validates the trust of the given jws.

        #  :param context: the request context
        #  :type context: satosa.context.Context
        #  :param jws: the jws to validate
        #  :type jws: str

        #  :raises: NotTrustedFederationError: raises an error if the trust evaluation fails.

        #  :return: the trust evaluation helper
        #  :rtype: TrustEvaluationHelper
        #  """

        #  self._log_debug(context, "[TRUST EVALUATION] evaluating trust.")

        #  headers = decode_jwt_header(jws)
        #  trust_eval = TrustEvaluationHelper(
            #  self.db_engine,
            #  httpc_params=self.config['network']['httpc_params'],
            #  **headers
        #  )

        #  try:
            #  trust_eval.evaluation_method()
        #  except EntryNotFound:
            #  message = (
            #  "[TRUST EVALUATION] not found for "
            #  f"{trust_eval.entity_id}"
            #  )
            #  self._log_error(context, message)
            #  raise NotTrustedFederationError(
            #  f"{trust_eval.entity_id} not found for Trust evaluation."
            #  )
        #  except Exception as e:
            #  message = (
            #  "[TRUST EVALUATION] failed for "
            #  f"{trust_eval.entity_id}: {e}"
            #  )
            #  self._log_error(context, message)
            #  raise NotTrustedFederationError(
            #  f"{trust_eval.entity_id} is not trusted."
            #  )

        #  return trust_eval

    @property
    def default_federation_private_jwk(self) -> dict:
        """Returns the default federation private jwk."""
        return tuple(self.federations_jwks_by_kids.values())[0]

    # era class FederationTrustModel(TrustEvaluator):

    #  def __init__(self, **kwargs):
        #  self.metadata_policy_resolver = TrustChainPolicy()
        #  self.federation_jwks = kwargs.get("federation_jwks", [])

    def get_public_keys(self, issuer):
        public_keys = [JWK(i).as_public_dict() for i in self.federation_jwks]

        return public_keys

    def _verify_trust_chain(self, trust_chain: list[str]):
        # TODO: qui c'è tutta la ciccia, ma si può fare copia incolla da terze parti (specialmente di pyeudiw.trust.__init__)
        raise NotImplementedError

    def get_verified_key(self, issuer: str, token_header: dict) -> ECKey | RSAKey | dict:
        # (1) verifica trust chain
        kid: str = token_header.get("kid", None)
        if not kid:
            raise ValueError("missing claim [kid] in token header")
        trust_chain: list[str] = token_header.get("trust_chain", None)
        if not trust_chain:
            raise ValueError("missing trust chain in federation token")
        if not isinstance(trust_chain, list):
            raise ValueError*("invalid format of header claim [trust_claim]")
        # TODO: check whick exceptions this might raise
        self._verify_trust_chain(trust_chain)

        # (2) metadata parsing ed estrazione Jwk set
        # TODO: wrap in something that implements VciJwksSource
        # apply policy of traust anchor only?
        issuer_entity_configuration = trust_chain[0]
        anchor_entity_configuration = trust_chain[-1]
        issuer_payload: dict = decode_jwt_payload(issuer_entity_configuration)
        anchor_payload = decode_jwt_payload(anchor_entity_configuration)
        trust_anchor_policy = anchor_payload.get("metadata_policy", {})
        final_issuer_metadata = self.metadata_policy_resolver.apply_policy(
            issuer_payload, trust_anchor_policy)
        metadata: dict = final_issuer_metadata.get("metadata", None)
        if not metadata:
            raise ValueError(
                "missing or invalid claim [metadata] in entity configuration")
        issuer_metadata: dict = metadata.get(
            FederationTrustModel._ISSUER_METADATA_TYPE, None)
        if not issuer_metadata:
            raise ValueError(
                f"missing or invalid claim [metadata.{FederationTrustModel._ISSUER_METADATA_TYPE}] in entity configuration")
        issuer_keys: list[dict] = issuer_metadata.get(
            "jwks", {}).get("keys", [])
        if not issuer_keys:
            raise ValueError(
                f"missing or invalid claim [metadata.{FederationTrustModel._ISSUER_METADATA_TYPE}.jwks.keys] in entity configuration")
        # check issuer = entity_id
        if issuer != (obt_iss := final_issuer_metadata.get("iss", "")):
            raise ValueError(
                f"invalid issuer metadata: expected '{issuer}', obtained '{obt_iss}'")

        # (3) dato il set completo, fa il match per kid tra l'header e il jwk set
        found_jwks: list[dict] = []
        for key in issuer_keys:
            obt_kid: str = key.get("kid", "")
            if kid == obt_kid:
                found_jwks.append(key)
        if len(found_jwks) != 1:
            raise ValueError(
                f"unable to uniquely identify a key with kid {kid} in appropriate section of issuer entity configuration")
        try:
            return key_from_jwk_dict(**found_jwks[0])
        except Exception as e:
            raise ValueError(f"unable to parse issuer jwk: {e}")

    # ---------------------------
    # TODO: sistema da qui in giù
    # ---------------------------

    # def __getattribute__(self, name: str) -> Any:
    #     if hasattr(self, name):
    #         return getattr(self, name)
    #     logger.critical("se vedi questo messaggio: sei perduto")
    #     return None

    def init_trust_resources(self) -> None:
        """
        Initializes the trust resources.
        """

        # private keys by kid
        self.federations_jwks_by_kids = {
            i['kid']: i for i in self.config['trust']['federation']['config']['federation_jwks']
        }
        # dumps public jwks
        self.federation_public_jwks = [
            key_from_jwk_dict(i).serialize() for i in self.config['trust']['federation']['config']['federation_jwks']
        ]
        # we close the connection in this constructor since it must be fork safe and
        # get reinitialized later on, within each fork
        self.update_trust_anchors()

        try:
            self.get_backend_trust_chain()
        except Exception as e:
            self._log_critical(
                "Backend Trust",
                f"Cannot fetch the trust anchor configuration: {e}"
            )

        self.db_engine.close()
        self._db_engine = None

    def entity_configuration_endpoint(self, context: Context) -> Response:
        """
        Entity Configuration endpoint.

        :param context: The current context
        :type context: Context

        :return: The entity configuration
        :rtype: Response
        """

        if context.qs_params.get('format', '') == 'json':
            return Response(
                json.dumps(self.entity_configuration_as_dict),
                status="200",
                content="application/json"
            )

        return Response(
            self.entity_configuration,
            status="200",
            content="application/entity-statement+jwt"
        )

    def update_trust_anchors(self):
        """
        Updates the trust anchors of current instance.
        """

        tas = self.config['trust']['federation']['config']['trust_anchors']
        self._log_info("Trust Anchors updates", f"Trying to update: {tas}")

        for ta in tas:
            try:
                self.update_trust_anchors_ecs(
                    db=self.db_engine,
                    trust_anchors=[ta],
                    httpc_params=self.config['network']['httpc_params']
                )
            except Exception as e:
                self._log_warning("Trust Anchor updates",
                                  f"{ta} update failed: {e}")

            self._log_info("Trust Anchor updates", f"{ta} updated")

    def get_backend_trust_chain(self) -> list[str]:
        """
        Get the backend trust chain. In case something raises an Exception (e.g. faulty storage), logs a warning message
        and returns an empty list.

        :return: The trust chain
        :rtype: list
        """
        try:
            trust_evaluation_helper = self.build_trust_chain_for_entity_id(
                storage=self.db_engine,
                entity_id=self.client_id,
                entity_configuration=self.entity_configuration,
                httpc_params=self.config['network']['httpc_params']
            )
            self.db_engine.add_or_update_trust_attestation(
                entity_id=self.client_id,
                attestation=trust_evaluation_helper.trust_chain,
                exp=trust_evaluation_helper.exp
            )
            return trust_evaluation_helper.trust_chain

        except (DiscoveryFailedError, EntryNotFound, Exception) as e:
            message = (
                f"Error while building trust chain for client with id: {self.client_id}. "
                f"{e.__class__.__name__}: {e}"
            )
            self._log_warning("Trust Chain", message)

        return []

#  class TrustEvaluationHelper:
    #  def __init__(self, storage: DBEngine, httpc_params, trust_anchor: str = None, **kwargs):
        #  self.exp: int = 0
        #  self.trust_chain: list[str] = []
        #  self.trust_anchor = trust_anchor
        #  self.storage = storage
        #  self.entity_id: str = ""
        #  self.httpc_params = httpc_params
        #  self.is_trusted = False

        #  for k, v in kwargs.items():
        #  setattr(self, k, v)

    def _get_evaluation_method(self):
        # The trust chain can be either federation or x509
        # If the trust_chain is empty, and we don't have a trust anchor
        if not self.trust_chain and not self.trust_anchor:
            raise MissingTrustType(
                "Static trust chain is not available"
            )

        try:
            if is_jwt_format(self.trust_chain[0]):
                return self.federation
        except TypeError:
            pass

        if is_der_format(self.trust_chain[0]):
            return self.x509

        raise InvalidTrustType(
            "Invalid Trust Type: trust type not supported"
        )

    def evaluation_method(self) -> bool:
        ev_method = self._get_evaluation_method()
        return ev_method()

    def _update_chain(self, entity_id: str | None = None, exp: datetime | None = None, trust_chain: list | None = None):
        if entity_id is not None:
            self.entity_id = entity_id

        if exp is not None:
            self.exp = exp

        if trust_chain is not None:
            self.trust_chain = trust_chain

    def _handle_federation_chain(self):
        _first_statement = decode_jwt_payload(self.trust_chain[-1])
        trust_anchor_eid = self.trust_anchor or _first_statement.get(
            'iss', None)

        if not trust_anchor_eid:
            raise UnknownTrustAnchor(
                "Unknown Trust Anchor: can't find 'iss' in the "
                f"first entity statement: {_first_statement} "
            )

        try:
            trust_anchor = self.storage.get_trust_anchor(trust_anchor_eid)
        except EntryNotFound:
            raise UnknownTrustAnchor(
                f"Unknown Trust Anchor: '{trust_anchor_eid}' is not "
                "a recognizable Trust Anchor."
            )

        decoded_ec = decode_jwt_payload(
            trust_anchor['federation']['entity_configuration']
        )
        jwks = decoded_ec.get('jwks', {}).get('keys', [])

        if not jwks:
            raise MissingProtocolSpecificJwks(
                f"Cannot find any jwks in {decoded_ec}"
            )

        tc = StaticTrustChainValidator(
            self.trust_chain, jwks, self.httpc_params
        )
        self._update_chain(
            entity_id=tc.entity_id,
            exp=tc.exp
        )

        _is_valid = False

        try:
            _is_valid = tc.validate()
        except TimeValidationError:
            logger.warn(f"Trust Chain {tc.entity_id} is expired")
        except Exception as e:
            logger.warn(
                f"Cannot validate Trust Chain {tc.entity_id} for the following reason: {e}")

        db_chain = None

        if not _is_valid:
            try:
                db_chain = self.storage.get_trust_attestation(
                    self.entity_id
                )["federation"]["chain"]
                if StaticTrustChainValidator(db_chain, jwks, self.httpc_params).is_valid:
                    self.is_trusted = True
                    return self.is_trusted

            except (EntryNotFound, Exception):
                pass

            _is_valid = tc.update()

            self._update_chain(
                trust_chain=tc.trust_chain,
                exp=tc.exp
            )

        # the good trust chain is then stored
        self.storage.add_or_update_trust_attestation(
            entity_id=self.entity_id,
            attestation=tc.trust_chain,
            exp=datetime.fromtimestamp(tc.exp)
        )

        self.is_trusted = _is_valid
        return _is_valid

    def _handle_x509_pem(self):
        trust_anchor_eid = self.trust_anchor or get_issuer_from_x5c(
            self.trust_chain)
        _is_valid = False

        if not trust_anchor_eid:
            raise UnknownTrustAnchor(
                "Unknown Trust Anchor: can't find 'iss' in the "
                "first entity statement"
            )

        try:
            trust_anchor = self.storage.get_trust_anchor(trust_anchor_eid)
        except EntryNotFound:
            raise UnknownTrustAnchor(
                f"Unknown Trust Anchor: '{trust_anchor_eid}' is not "
                "a recognizable Trust Anchor."
            )

        pem = trust_anchor['x509'].get('pem')

        if pem is None:
            raise MissingTrustType(
                f"Trust Anchor: '{trust_anchor_eid}' has no x509 trust entity"
            )

        try:
            _is_valid = verify_x509_anchor(pem)
        except Exception as e:
            raise InvalidAnchor(
                f"Anchor verification raised the following exception: {e}"
            )

        if not self.is_trusted and trust_anchor['federation'].get("chain", None) is not None:
            self._handle_federation_chain()

        self.is_trusted = _is_valid
        return _is_valid

    def federation(self) -> bool:
        if len(self.trust_chain) == 0:
            self.discovery(self.entity_id)

        if self.trust_chain:
            self.is_valid = self._handle_federation_chain()
            return self.is_valid

        return False

    def x509(self) -> bool:
        self.is_valid = self._handle_x509_pem()
        return self.is_valid

    def get_final_metadata(self, metadata_type: str, policies: list[dict]) -> dict:
        policy_acc = {"metadata": {}, "metadata_policy": {}}

        for policy in policies:
            policy_acc = combine(policy, policy_acc)

        self.final_metadata = decode_jwt_payload(self.trust_chain[0])

        try:
            # TODO: there are some cases where the jwks are taken from a uri ...
            selected_metadata = {
                "metadata": self.final_metadata['metadata'],
                "metadata_policy": {}
            }

            self.final_metadata = TrustChainPolicy().apply_policy(
                selected_metadata,
                policy_acc
            )

            return self.final_metadata["metadata"][metadata_type]
        except KeyError:
            raise ProtocolMetadataNotFound(
                f"{metadata_type} not found in the final metadata:"
                f" {self.final_metadata['metadata']}"
            )

    def get_trusted_jwks(self, metadata_type: str, policies: list[dict] = []) -> list[dict]:
        return self.get_final_metadata(
            metadata_type=metadata_type,
            policies=policies
        ).get('jwks', {}).get('keys', [])

    def discovery(self, entity_id: str, entity_configuration: EntityStatement | None = None):
        """
        Updates fields ``trust_chain`` and ``exp`` based on the discovery process.

        :raises: DiscoveryFailedError: raises an error if the discovery fails.
        """
        trust_anchor_eid = self.trust_anchor
        _ta_ec = self.storage.get_trust_anchor(entity_id=trust_anchor_eid)
        ta_ec = _ta_ec['federation']['entity_configuration']

        tcbuilder = TrustChainBuilder(
            subject=entity_id,
            trust_anchor=trust_anchor_eid,
            trust_anchor_configuration=ta_ec,
            subject_configuration=entity_configuration,
            httpc_params=self.httpc_params
        )

        self._update_chain(
            trust_chain=tcbuilder.get_trust_chain(),
            exp=tcbuilder.exp
        )
        is_good = tcbuilder.is_valid
        if not is_good:
            raise DiscoveryFailedError(
                f"Discovery failed for entity {entity_id} with configuration {entity_configuration}"
            )

    #  @staticmethod
    #  def build_trust_chain_for_entity_id(storage: DBEngine, entity_id, entity_configuration, httpc_params):
        #  """
        #  Builds a ``TrustEvaluationHelper`` and returns it if the trust chain is valid.
        #  In case the trust chain is invalid, tries to validate it in discovery before returning it.

        #  :return: The svg data for html, base64 encoded
        #  :rtype: str
        #  """
        #  db_chain = storage.get_trust_attestation(entity_id)

        #  trust_evaluation_helper = TrustEvaluationHelper(
            #  storage=storage,
            #  httpc_params=httpc_params,
            #  trust_chain=db_chain
        #  )

        #  is_good = trust_evaluation_helper.evaluation_method()
        #  if is_good:
            #  return trust_evaluation_helper

        #  trust_evaluation_helper.discovery(
            #  entity_id=entity_id, entity_configuration=entity_configuration)
        #  return trust_evaluation_helper

    def update_trust_anchors_ecs(self, trust_anchors: list[str], db: DBEngine) -> None:
        """
        Update the trust anchors entity configurations.

        :param trust_anchors: The trust anchors
        :type trust_anchors: list
        :param db: The database engine
        :type db: DBEngine
        :param httpc_params: The HTTP client parameters
        :type httpc_params: dict
        """

        ta_ecs = get_entity_configurations(
            trust_anchors, httpc_params=self.httpc_params
        )

        for jwt in ta_ecs:
            if isinstance(jwt, bytes):
                jwt = jwt.decode()

            ec = EntityStatement(jwt, httpc_params=self.httpc_params)
            if not ec.validate_by_itself():
                logger.warning(
                    f"The trust anchor failed the validation of its EntityConfiguration {ec}")

            db.add_trust_anchor(
                entity_id=ec.sub,
                entity_configuration=ec.jwt,
                exp=ec.exp
            )
