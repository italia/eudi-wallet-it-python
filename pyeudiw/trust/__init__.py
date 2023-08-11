from datetime import datetime
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.storage.db_engine import DBEngine


class TrustEvaluationHelper:
    def __init__(self, storage: DBEngine, **kwargs):
        self.exp: int = 0
        self.trust_chain: list = []
        self.storage = storage
        self.entity_id: str = ""

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def evaluation_method(self):
        # TODO: implement automatic detection of trust evaluation
        # method based on internal trust evaluetion property
        return self.federation

    def _handle_chain(self, trust_chain: list[str], jwks: list[dict]):
        tc = StaticTrustChainValidator(trust_chain, jwks)
        self.entity_id = tc.get_entityID()

        _is_valid = tc.is_valid
        self.exp = tc.get_exp()

        if not _is_valid:
            db_chain = self.storage.find_chain(self.entity_id)[
                "federation"]["chain"]

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
            return self._handle_chain(self.trust_chain, self.jwks)

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
