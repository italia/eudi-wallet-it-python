from datetime import datetime
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.federation.exceptions import ProtocolMetadataNotFound
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.jwt.utils import unpad_jwt_payload, is_jwt_format
from pyeudiw.x509.verify import verify_x509_anchor, get_issuer_from_x5c, is_der_format

from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust.exceptions import (
    MissingProtocolSpecificJwks,
    UnknownTrustAnchor,
    InvalidTrustType,
    MissingTrustType
)


class TrustEvaluationHelper:
    def __init__(self, storage: DBEngine, httpc_params, trust_anchor: str = None, **kwargs):
        self.exp: int = 0
        self.trust_chain: list = []
        self.trust_anchor = trust_anchor
        self.storage = storage
        self.entity_id: str = ""
        self.httpc_params = httpc_params
        self.is_trusted = False

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def evaluation_method(self) -> bool:
        if not (type(self.trust_chain) is list) or len(self.trust_chain) == 0:
            raise MissingTrustType(
                "Missing Trust Type: can't find 'typ' in headers"
            )

        if is_jwt_format(self.trust_chain[0]):
            return self.federation
        elif is_der_format(self.trust_chain[0]):
            return self.x509

        raise InvalidTrustType(
            "Invalid Trust Type: trust type not supported"
        )

    def _handle_federation_chain(self):
        _first_statement = unpad_jwt_payload(self.trust_chain[-1])
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

        decoded_ec = unpad_jwt_payload(
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
        self.entity_id = tc.entity_id
        self.exp = tc.exp
        _is_valid = False
        try:
            _is_valid = tc.validate()
        except Exception:
            # raise / log here that's expired
            pass  # nosec - B110
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
            self.exp = tc.exp
            self.trust_chain = tc.trust_chain

        # the good trust chain is then stored
        self.storage.add_or_update_trust_attestation(
            entity_id=self.entity_id,
            attestation=tc.trust_chain,
            exp=datetime.fromtimestamp(tc.exp)
        )

        self.is_trusted = _is_valid
        return _is_valid
    
    def _handle_x509_pem(self):
        trust_anchor_eid = self.trust_anchor or get_issuer_from_x5c(self.x5c)

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

        pem = trust_anchor['x509']['pem']

        _is_valid = verify_x509_anchor(pem)

        if not self.is_trusted and trust_anchor['federation'].get("chain", None) != None:
            self._handle_federation_chain()

        self.is_trusted = _is_valid
        return _is_valid

    def federation(self) -> bool:
        if self.trust_chain:
            self.is_valid = self._handle_federation_chain()
            return self.is_valid

        # TODO - at least a TA entity id is required for a discovery process
        # _tc = TrustChainBuilder(
            # subject= self.entity_id,
            # trust_anchor=trust_anchor_ec,
            # trust_anchor_configuration=trust_anchor_ec
        # )
        # if _tc.is_valid:
            # self.trust_chain = _tc.serialize()
            # return self.trust_chain

        return []

    def x509(self) -> bool:
        self.is_valid = self._handle_x509_pem()
        return self.is_valid

    def get_final_metadata(self, metadata_type: str) -> dict:
        # TODO - apply metadata policy and get the final metadata
        # for now the final_metadata is the EC metadata -> TODO final_metadata
        self.final_metadata = unpad_jwt_payload(self.trust_chain[0])
        try:
            # TODO: there are some cases where the jwks are taken from a uri ...
            return self.final_metadata['metadata'][metadata_type]
        except KeyError:
            raise ProtocolMetadataNotFound(
                f"{metadata_type} not found in the final metadata:"
                f" {self.final_metadata}"
            )

    def get_trusted_jwks(self, metadata_type: str) -> list:
        return self.get_final_metadata(
            metadata_type=metadata_type
        ).get('jwks', {}).get('keys', [])
