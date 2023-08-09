from datetime import datetime
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
from pyeudiw.storage.base_storage import BaseStorage
from pyeudiw.trust.exceptions import NoTrustChainProvided

class TrustEvaluationHelper:
    def __init__(self, entityid: str, storage: BaseStorage,  **kwargs):
        self.entityid = entityid
        self.exp = None
        self.trust_chain = None
        self.storage = storage
        
        for k, v in kwargs.items():
            setattr(self, k, v)
            
    def inspect_evaluation_method(self):
        # TODO: implement automatic detection of trust evaluation 
        # method based on internal trust evaluetion property 
        return self.federation
    
    def _handle_chain(self, trust_chain: list[str]):
        tc = StaticTrustChainValidator(trust_chain)
        _is_valid = tc.is_valid
        self.exp = tc.get_exp()

        if not _is_valid:
            db_chain = self.storage.find_chain(tc.get_entityID())["federation"]["chain"]
            
            if db_chain is not None and \
                StaticTrustChainValidator(db_chain).is_valid:
                return True

            _is_valid = tc.update()
            self.exp = tc.get_exp()
            self.trust_chain = tc.get_chain()
            
            if db_chain is None:
                self.storage.add_chain(tc.get_entityID(), tc.get_chain(), datetime.fromtimestamp(tc.get_exp()))
            else:
                self.storage.update_chain(tc.get_entityID(), tc.get_chain(), datetime.fromtimestamp(tc.get_exp()))

        return _is_valid
    
    def federation(self):
        trust_chain = getattr(self, "trust_chain", None)
        
        if trust_chain:
            return self._handle_chain(trust_chain)
        
        raise NoTrustChainProvided("This instance of TrustEvaluationHelper has no \"trust_chain\" field")
    
    def x509(self):
        pass