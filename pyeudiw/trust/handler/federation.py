import json
import logging
import inspect
from typing import Any, Callable, List, Union

from satosa.context import Context
from satosa.response import Response

from pyeudiw.federation.exceptions import TimeValidationError
from pyeudiw.federation.policy import TrustChainPolicy
from pyeudiw.federation.statements import get_entity_configurations
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.jwk import JWK
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.tools.utils import exp_from_now, iat_now
from pyeudiw.trust.exceptions import MissingProtocolSpecificJwks, UnknownTrustAnchor
from pyeudiw.trust.handler.commons import DEFAULT_HTTPC_PARAMS
from pyeudiw.trust.handler.interface import TrustHandlerInterface
from pyeudiw.trust.model.trust_source import TrustEvaluationType, TrustSourceData
from ...tools.http import http_get

logger = logging.getLogger(__name__)

_ISSUER_METADATA_TYPE = "openid_credential_issuer"


class FederationHandler(TrustHandlerInterface, BaseLogger):

    _TRUST_TYPE = "federation"
    _TRUST_PARAMETER_NAME = "trust_chain"

    def __init__(
        self,
        metadata: dict,
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
        include_issued_jwt_header_param: bool = False,
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
        self.client_id: str = federation_entity_metadata.get("iss", client_id)
        self.entity_configuration_exp = entity_configuration_exp
        self.include_issued_jwt_header_param = include_issued_jwt_header_param

        self.federation_public_jwks = [
            JWK(i).as_public_dict() for i in self.federation_jwks
        ]

        if isinstance(self.metadata["jwks"], dict) and self.metadata["jwks"].get(
            "keys"
        ):
            self.metadata["jwks"] = self.metadata["jwks"].pop("keys")

        self.metadata_jwks = [JWK(i) for i in self.metadata["jwks"]]
        self.metadata["jwks"] = {
            "keys": [i.as_public_dict() for i in self.metadata_jwks]
        }

        self.metadata_policy_resolver = TrustChainPolicy()

        for k, v in kwargs.items():
            if not hasattr(self, k):
                logger.warning(
                    f"Trust - FederationHandler. {k} was provided in the init but not handled."
                )

    def extract_and_update_trust_materials(self, issuer, trust_source):
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [issuer: {issuer}, trust_source: {trust_source}]"
        )
        # check if issuer is not null
        if issuer:
            #check entity configuration for issuer
            metadata = ""
            try:
                metadata = http_get(f'{issuer.strip("/")}/.well-known/openid-federation')
            except Exception as e:
                logger.warning(f"Cannot fetch metadata for issuer {issuer}: {e}")
            if not metadata:
                logger.warning("Cannot find metadata for issuer, cannot extract trust materials.")
                return trust_source
            metadata_list = [self.__get_entity_configuration(authority) for authority in metadata["authority_hints"]]
            if not metadata_list:
                logger.warning("Cannot find metadata for issuer authorities, cannot extract trust materials.")
            for metadata_ta in metadata_list:
                subordinate_statement = self.__get_subordinate_statement(metadata_ta, issuer)
                if subordinate_statement:
                    check = self.__check_subordinate_statement(subordinate_statement, metadata_ta, issuer)
                    if check:
                        _jwk = self.__get_jwks_keys(metadata)
                        trust_source.add_trust_param(
                            FederationHandler._TRUST_TYPE,
                            TrustEvaluationType(
                                attribute_name=FederationHandler._TRUST_PARAMETER_NAME,
                                trust_chain=metadata.get("metadata", {}).get("federation_entity", {}).get("federation_fetch_endpoint",""), # @Todo We need to talking with Giuseppe
                                jwks=_jwk,
                                expiration_date=0,
                                trust_handler_name=str(self.__class__.__name__),
                            ),
                        )
                        break
        return trust_source

    def __get_jwks_keys(self, metadata: dict) -> list:
        md = metadata.get("metadata", {})
        provider = (
                md.get("wallet_solution")
                or md.get("openid_credential_verifier")
                or md.get("openid_credential_issuer")
                or {}
        )
        if provider:
            return provider.get("jwks", {}).get("keys", [])
        return md.get("jwks", {}).get("keys", [])

    def __check_subordinate_statement(self, jwt: str, metadata_trust_anchor: dict, sub: str ) -> bool:
        """
        Check if the given JWT is a valid subordinate statement for trust anchor.
        :param jwt: The JWT to check
        :param metadata_trust_anchor: The metadata of the trust anchor to check against
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [sub: {sub}]"
        )
        _jwk = JWK(metadata_trust_anchor["jwks"]["keys"][0]) # @Todo we should check all the jwks, but for now we take the first one. Talking with Giuseppe about it.
        jwshelper = JWSHelper(_jwk.as_dict())
        try:
            jwshelper.verify(jwt)
            output = decode_jwt_payload(jwt)
            if output.get("sub") != sub:
                logger.warning(f"Subordinate statement sub {output.get('sub')} does not match expected sub {sub}")
                return False
            return True
        except Exception as e:
            logger.warning(f"Cannot verify subordinate statement: {e}")
            return False

    def __get_subordinate_statement(self, metadata: dict, endpoint: str) -> str:
        """
        Get the subordinate statement for the given endpoint.
        :param endpoint: The endpoint to get the subordinate statement for
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [metadata: {metadata}, endpoint: {endpoint}]"
        )
        fetch_endpoint = metadata.get("metadata", {}).get("federation_entity", {}).get("federation_fetch_endpoint","")
        if not fetch_endpoint:
            logger.warning(f"Cannot find fetch endpoint, cannot get subordinate statement.")
        jwt = http_get(f'{fetch_endpoint.strip("/")}?sub={endpoint}', decode_output= False)
        return jwt


    def __get_entity_configuration(self, endpoint: str) -> str:
        """
        Check if the given endpoint is a trust anchor.
        :param endpoint: The endpoint to check
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [endpoint: {endpoint}]"
        )
        metadata_ta = http_get(f'{endpoint.strip("/")}/.well-known/openid-federation')
        if not metadata_ta:
            logger.warning(f"Cannot find metadata for endpoint {endpoint}, cannot check if it's a trust anchor.")
        return metadata_ta

    def get_metadata(self, issuer, trust_source):
        return trust_source

    @property
    def entity_configuration(self) -> str:
        """
        Returns the entity configuration as a JWT.

        :return: The entity configuration
        :rtype: str
        """

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

    def entity_configuration_endpoint(self, context: Context, *args ) -> Response:
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
            return Response(
                self.entity_configuration,
                status="200",
                content="application/entity-statement+jwt",
            )

    def build_metadata_endpoints(
        self, backend_name: str, entity_uri: str
    ) -> list[tuple[str, Callable[[Context, Any], Response]]]:
        metadata_path = f'{backend_name.strip("/")}/.well-known/openid-federation'
        return [(metadata_path, self.entity_configuration_endpoint)]

    def get_handled_trust_material_name(self) -> str:
        return FederationHandler._TRUST_PARAMETER_NAME

    def extract_jwt_header_trust_parameters(
        self, trust_source: TrustSourceData
    ) -> dict:
        tp: dict = trust_source.serialize().get(FederationHandler._TRUST_TYPE, {})
        if trust_chain := tp.get(FederationHandler._TRUST_PARAMETER_NAME, None):
            return {"trust_chain": trust_chain}
        return {}

    def validate_trust_material(
        self,
        chain: list[str],
        trust_source: TrustSourceData,
    ) -> tuple[bool, TrustSourceData]:
        """
        Validate the trust chain of the trust source.

        :param trust_source: The trust source
        :type trust_source: TrustSourceData

        :returns: If the trust chain is valid
        :rtype: bool
        """

        _first_statement = decode_jwt_payload(chain[-1])
        trust_anchor_eid = _first_statement.get("iss", None)

        if not trust_anchor_eid:
            raise UnknownTrustAnchor(
                "Unknown Trust Anchor: can't find 'iss' in the "
                f"first entity statement: {_first_statement} "
            )

        if trust_anchor_eid not in self.trust_anchors:
            raise UnknownTrustAnchor(
                f"Unknown Trust Anchor: '{trust_anchor_eid}' is not "
                "a recognizable Trust Anchor."
            )

        if len(self.trust_anchors[trust_anchor_eid]) != 0:
            jwks = self.trust_anchors[trust_anchor_eid]
        else:
            try:
                trust_anchor = get_entity_configurations(
                    trust_anchor_eid, self.httpc_params, False
                )
                decoded_ec = decode_jwt_payload(
                    trust_anchor["federation"]["entity_configuration"]
                )
                jwks = decoded_ec.get("jwks", {}).get("keys", [])
            except Exception as e:
                raise UnknownTrustAnchor(
                    f"Cannot fetch Trust Anchor '{trust_anchor_eid}' entity configuration: {e}"
                ) from e

        if not jwks:
            raise MissingProtocolSpecificJwks(
                f"Cannot find any jwks in for the Trust Anchor '{trust_anchor_eid}'"
            )

        tc = StaticTrustChainValidator(chain, jwks, self.httpc_params)

        _is_valid = False

        try:
            _is_valid = tc.validate()
        except TimeValidationError:
            logger.warning(f"Trust Chain {tc.entity_id} is expired")
        except Exception as e:
            logger.warning(
                f"Cannot validate Trust Chain {tc.entity_id} for the following reason: {e}"
            )

        db_chain = None

        if not _is_valid:
            try:
                db_chain = getattr(trust_source, "federation").trust_chain

                if StaticTrustChainValidator(
                    db_chain, jwks, self.httpc_params
                ).is_valid:
                    self.is_trusted = True
                    return self.is_trusted, trust_source

            except (EntryNotFound, Exception):
                pass

            _is_valid = tc.update()

        leaf_jwks = decode_jwt_payload(chain[0]).get("jwks", {}).get("keys", [])

        # the good trust chain is then stored
        trust_source.add_trust_param(
            FederationHandler._TRUST_TYPE,
            TrustEvaluationType(
                attribute_name=FederationHandler._TRUST_PARAMETER_NAME,
                trust_chain=chain,
                jwks=[JWK(key=jwk).as_dict() for jwk in leaf_jwks],
                expiration_date=0,
                trust_handler_name=str(self.__class__.__name__),
            ),
        )

        return _is_valid, trust_source
