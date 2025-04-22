import json
import logging
import satosa
from typing import Any, Callable, List, Union
from satosa.response import Response

from pyeudiw.federation.exceptions import TimeValidationError
from pyeudiw.federation.policy import TrustChainPolicy
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.jwk import JWK
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.trust.exceptions import MissingProtocolSpecificJwks, UnknownTrustAnchor
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustSourceData, TrustEvaluationType
from pyeudiw.federation.statements import (
    get_entity_configurations,
    get_entity_statements,
)

from .commons import DEFAULT_HTTPC_PARAMS

logger = logging.getLogger(__name__)

_ISSUER_METADATA_TYPE = "openid_credential_issuer"


class FederationHandler(TrustHandlerInterface, BaseLogger):

    _TRUST_TYPE = "federation"
    _TRUST_PARAMETER_NAME = "trust_chain"

    def __init__(
        self,
        metadata: List[dict],
        authority_hints: List[str],
        trust_anchors: dict[str, dict[str, str]],
        default_sig_alg: str,
        federation_jwks: List[dict[str, Union[str, List[str]]]],
        trust_marks: List[dict],
        federation_entity_metadata: dict[str, str],
        client_id: str,
        entity_configuration_exp: int = 800,
        httpc_params: dict = DEFAULT_HTTPC_PARAMS,
        cache_ttl: int = 0,
        metadata_type: str = _ISSUER_METADATA_TYPE,
        **kwargs,
    ):

        self.httpc_params = httpc_params
        self.cache_ttl = cache_ttl
        # TODO - this MUST be handled in httpc_params ...
        self.http_async_calls = False
        self.client_id = client_id

        self.metadata_type = metadata_type
        self.metadata: dict = metadata
        self.authority_hints: List[str] = authority_hints
        self.trust_anchors: dict[str, dict[str, str]] = trust_anchors
        self.default_sig_alg: str = default_sig_alg
        self.federation_jwks: List[dict[str, Union[str, List[str]]]] = federation_jwks
        self.trust_marks: List[dict] = trust_marks
        self.federation_entity_metadata: dict[str, str] = federation_entity_metadata
        self.client_id: str = federation_entity_metadata
        self.entity_configuration_exp = entity_configuration_exp

        self.federation_public_jwks = [
            JWK(i).as_public_dict() for i in self.federation_jwks
        ]

        if isinstance(self.metadata["jwks"], dict) and self.metadata["jwks"].get('keys'):
            self.metadata["jwks"] = self.metadata["jwks"].pop("keys")

        self.metadata_jwks = [JWK(i) for i in self.metadata["jwks"]]
        self.metadata["jwks"] = {"keys": [
            i.as_public_dict() for i in self.metadata_jwks
        ]}
        
        self.metadata_policy_resolver = TrustChainPolicy()
        
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
                "typ": "entity-statement+jwt",
            },
            plain_dict=data,
        )

    @property
    def entity_configuration_as_dict(self) -> dict:
        """Returns the entity configuration as a dictionary."""
        ec_payload = {
            "exp": exp_from_now(minutes=self.entity_configuration_exp),
            "iat": iat_now(),
            "iss": self.client_id,
            "sub": self.client_id,
            "jwks": {"keys": self.federation_public_jwks},
            "metadata": {
                self.metadata_type: self.metadata,
                "federation_entity": self.federation_entity_metadata,
            },
            "authority_hints": self.authority_hints,
        }
        return ec_payload

    def entity_configuration_endpoint(
        self, context: satosa.context.Context
    ) -> satosa.response.Response:
        """
        Entity Configuration endpoint.

        :param context: The current context
        :type context: Context

        :return: The entity configuration
        :rtype: Response
        """

        if context.qs_params.get("format", "") == "json":
            return Response(
                json.dumps(self.entity_configuration_as_dict),
                status="200",
                content="application/json",
            )
        else:
            return satosa.response.Response(
                self.entity_configuration,
                status="200",
                content="application/entity-statement+jwt",
            )

    def build_metadata_endpoints(
        self, backend_name: str, entity_uri: str
    ) -> list[
        tuple[str, Callable[[satosa.context.Context, Any], satosa.response.Response]]
    ]:

        metadata_path = f'^{backend_name.strip("/")}/.well-known/openid-federation$'
        response = self.entity_configuration

        def metadata_response_fn(
            ctx: satosa.context.Context, *args
        ) -> satosa.response.Response:
            return JsonResponse(message=response)

        return [(metadata_path, metadata_response_fn)]
    
    def get_handled_trust_material_name(self) -> str:
        return FederationHandler._TRUST_PARAMETER_NAME
        
    def extract_jwt_header_trust_parameters(self, trust_source: TrustSourceData) -> dict:
        tp: dict = trust_source.serialize().get(FederationHandler._TRUST_TYPE, {})
        if (trust_chain := tp.get(FederationHandler._TRUST_PARAMETER_NAME, None)):
            return {"trust_chain": trust_chain}
        return {}
    
    def validate_trust_material(
            self, 
            trust_chain: list[str], 
            trust_source: TrustSourceData,
        ) -> dict[bool, TrustSourceData]:
        """
        Validate the trust chain of the trust source.

        :param trust_source: The trust source
        :type trust_source: TrustSourceData

        :returns: If the trust chain is valid
        :rtype: bool
        """
        _first_statement = decode_jwt_payload(trust_chain[-1])
        trust_anchor_eid = _first_statement.get('iss', None)

        if not trust_anchor_eid:
            raise UnknownTrustAnchor(
                "Unknown Trust Anchor: can't find 'iss' in the "
                f"first entity statement: {_first_statement} "
            )
        
        if not trust_anchor_eid in self.trust_anchors:
            raise UnknownTrustAnchor(
                f"Unknown Trust Anchor: '{trust_anchor_eid}' is not "
                "a recognizable Trust Anchor."
            )
        
        if len(self.trust_anchors[trust_anchor_eid]) != 0:
            jwks = self.trust_anchors[trust_anchor_eid]
        else:
            try:
                trust_anchor = get_entity_configurations(trust_anchor_eid, self.httpc_params, False)
                decoded_ec = decode_jwt_payload(
                    trust_anchor['federation']['entity_configuration']
                )
                jwks = decoded_ec.get('jwks', {}).get('keys', [])
            except Exception as e:
                raise UnknownTrustAnchor(
                    f"Cannot fetch Trust Anchor '{trust_anchor_eid}' entity configuration: {e}"
                ) from e

        if not jwks:
            raise MissingProtocolSpecificJwks(
                f"Cannot find any jwks in for the Trust Anchor '{trust_anchor_eid}'"
            )

        tc = StaticTrustChainValidator(
            trust_chain, jwks, self.httpc_params
        )

        _is_valid = False

        try:
            _is_valid = tc.validate()
        except TimeValidationError:
            logger.warning(f"Trust Chain {tc.entity_id} is expired")
        except Exception as e:
            logger.warning(
                f"Cannot validate Trust Chain {tc.entity_id} for the following reason: {e}")

        db_chain = None

        if not _is_valid:
            try:
                db_chain = trust_source.federation.trust_chain
                if StaticTrustChainValidator(db_chain, jwks, self.httpc_params).is_valid:
                    self.is_trusted = True
                    return self.is_trusted

            except (EntryNotFound, Exception):
                pass

            _is_valid = tc.update()

        leaf_jwks = decode_jwt_payload(trust_chain[0]).get('jwks', {}).get('keys', [])

        # the good trust chain is then stored
        trust_source.add_trust_param(
            FederationHandler._TRUST_TYPE,
            TrustEvaluationType(
                attribute_name=FederationHandler._TRUST_PARAMETER_NAME,
                trust_chain=trust_chain,
                jwks=[JWK(key=jwk).as_dict() for jwk in leaf_jwks],
                expiration_date=None,
                trust_handler_name=str(self.__class__.__name__),
            )
        )
        
        return _is_valid, trust_source
