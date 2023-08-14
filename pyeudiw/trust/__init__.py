from datetime import datetime
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.jwt.utils import unpad_jwt_payload

from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust.exceptions import UnknownTrustAnchor


class TrustEvaluationHelper:
    def __init__(self, storage: DBEngine, httpc_params, **kwargs):
        self.exp: int = 0
        self.trust_chain: list = []
        self.storage = storage
        self.entity_id: str = ""
        self.httpc_params = httpc_params,

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def evaluation_method(self):
        # TODO: implement automatic detection of trust evaluation
        # method based on internal trust evaluetion property
        return self.federation

    def _handle_chain(self):

        trust_anchor_eid = unpad_jwt_payload(
            self.trust_chain[-1]).get('iss', None)

        try:
            trust_anchor = self.storage.get_trust_anchor(trust_anchor_eid)
        except EntryNotFound:
            return False

        if not trust_anchor:
            raise UnknownTrustAnchor(
                f"Unknown Trust Anchor '{trust_anchor_eid}'"
            )

        jwks = trust_anchor['federation']['entity_configuration']['jwks']['keys']
        tc = StaticTrustChainValidator(
            self.trust_chain, jwks, self.httpc_params
        )

        self.entity_id = tc.get_entityID()
        self.exp = tc.get_exp()

        _is_valid = tc.is_valid
        if not _is_valid:
            db_chain = self.storage.get_trust_attestation(
                self.entity_id
            )["federation"]["chain"]

            if db_chain is not None and \
                    StaticTrustChainValidator(db_chain).is_valid:
                return True

            _is_valid = tc.update()
            self.exp = tc.get_exp()
            self.trust_chain = tc.get_chain()

            if db_chain is None:
                self.storage.add_chain(
                    self.entity_id, tc.get_chain(), datetime.fromtimestamp(tc.get_exp()))
            else:
                self.storage.update_chain(
                    self.entity_id, tc.get_chain(), datetime.fromtimestamp(tc.get_exp()))

        return _is_valid

    def federation(self) -> bool:
        if self.trust_chain:
            self.is_valid = self._handle_chain()
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

    def x509(self):
        raise NotImplementedError("X.509 is not supported in this release")

    def get_final_metadata(self, metadata_type: str) -> dict:
        # TODO - apply metadata policy and get the final metadata
        # for now the final_metadata is the EC metadata -> TODO final_metadata
        self.final_metadata = unpad_jwt_payload(self.trust_chain[0])
        return self.final_metadata

    def get_trusted_jwks(self, metadata_type: str) -> list:
        return self.get_final_metadata(
            metadata_type=metadata_type
        ).get('jwks', {}).get('keys', [])
