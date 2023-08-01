from pyeudiw.federation.statements import (
    get_entity_configurations,
    EntityStatement,
)
from pyeudiw.jwt.utils import unpad_jwt_payload


logger = logging.getLogger("pyeudiw.federation")


class StaticTrustChainValidator:
    def __init__(
        self,
        static_trust_chain :list,
        trust_anchor_jwks :list
        **kwargs,
    ) -> None:
        
        self.static_trust_chain = static_trust_chain
        self.updated_trust_chain = []
        self.trust_anchor_jwks = trust_anchor_jwks
        for k,v in kwargs.items():
            setattr(self, k, v)
    
    @property
    def is_valid(self):
        exps = []
        
        # start from the last entity statement
        rev_tc = [
            i for i in reversed(
                self.updated_trust_chain or self.static_trust_chain
            )
        ]
        
        # inspect the entity statement kid header to know which 
        # TA's public key to use for the validation
        
        # if valid: exps.append(this-exp)
        
        fed_jwks = unpad_jwt_payload(rev_tc[0])['jwks']['keys']
        # for st in rev_tc[1:]:
        # validate the entire chain taking in cascade using fed_jwks
        # if valid -> update fed_jwks with $st
    
    def update(self):
        
        
        for st in self.static_trust_chain:
            # if EC -> download again from well-known/openid-federation
            # if ES:
            #   if source_endpoint is available -> take it directly from it
            # else:
            #   get the EC of the issuer and then take the statement from the fetch
            
            # if ok -> self.updated_trust_chain.append(new_es)
        
        return self.is_valid
            
        
        
