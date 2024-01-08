import logging
from datetime import datetime

from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.federation.exceptions import ProtocolMetadataNotFound
from pyeudiw.satosa.exceptions import DiscoveryFailedError
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.jwt.utils import decode_jwt_payload, is_jwt_format
from pyeudiw.x509.verify import verify_x509_anchor, get_issuer_from_x5c, is_der_format

from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust.exceptions import (
    MissingProtocolSpecificJwks,
    UnknownTrustAnchor,
    InvalidTrustType,
    MissingTrustType,
    InvalidAnchor
)

from pyeudiw.federation.statements import EntityStatement
from pyeudiw.federation.exceptions import TimeValidationError
from pyeudiw.federation.policy import TrustChainPolicy, combine

logger = logging.getLogger(__name__)

class TrustEvaluationHelper:
    def __init__(self, storage: DBEngine, httpc_params, trust_anchor: str = None, **kwargs):
        self.exp: int = 0
        self.trust_chain: list[str] = []
        self.trust_anchor = trust_anchor
        self.storage = storage
        self.entity_id: str = ""
        self.httpc_params = httpc_params
        self.is_trusted = False

        for k, v in kwargs.items():
            setattr(self, k, v)

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
        if entity_id != None:
            self.entity_id = entity_id

        if exp != None:
            self.exp = exp

        if trust_chain != None:
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
            logger.warn(f"Cannot validate Trust Chain {tc.entity_id} for the following reason: {e}")

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
        trust_anchor_eid = self.trust_anchor or get_issuer_from_x5c(self.trust_chain)
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

        if pem == None:
            raise MissingTrustType(
                f"Trust Anchor: '{trust_anchor_eid}' has no x509 trust entity"
            )

        try:
            _is_valid = verify_x509_anchor(pem)
        except Exception as e:
            raise InvalidAnchor(
                f"Anchor verification raised the following exception: {e}"
            )
            

        if not self.is_trusted and trust_anchor['federation'].get("chain", None) != None:
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
                f"Discovery failed for entity {entity_id}\nwith configuration {entity_configuration}")

    @staticmethod
    def build_trust_chain_for_entity_id(storage: DBEngine, entity_id, entity_configuration, httpc_params):
        """
        Builds a ``TrustEvaluationHelper`` and returns it if the trust chain is valid.
        In case the trust chain is invalid, tries to validate it in discovery before returning it.

        :return: The svg data for html, base64 encoded
        :rtype: str
        """
        db_chain = storage.get_trust_attestation(entity_id)

        trust_evaluation_helper = TrustEvaluationHelper(
            storage=storage,
            httpc_params=httpc_params,
            trust_chain=db_chain
        )

        is_good = trust_evaluation_helper.evaluation_method()
        if is_good:
            return trust_evaluation_helper

        trust_evaluation_helper.discovery(entity_id=entity_id, entity_configuration=entity_configuration)
        return trust_evaluation_helper


